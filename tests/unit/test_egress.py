from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from capgate.sandbox.egress import (
    DNS_REBINDING_RULE_ID,
    HOST_INVALID_RULE_ID,
    HOST_NOT_ALLOWED_RULE_ID,
    HOST_PROHIBITED_RULE_ID,
    REQUEST_CONTRACT_RULE_ID,
    RESOLUTION_INVALID_RULE_ID,
    RESOLUTION_PROHIBITED_RULE_ID,
    EgressPolicy,
    EgressPolicyError,
    EgressRequest,
    RequestContract,
    ResolverResult,
    check_host,
    check_redirect,
    check_request,
    normalize_hostname,
    validate_resolution,
)


def _contract(**changes: object) -> RequestContract:
    values: dict[str, object] = {
        "tool": "fetch_docs",
        "schemes": frozenset({"https"}),
        "methods": frozenset({"GET"}),
        "path_prefixes": ("/v1/docs",),
    }
    values.update(changes)
    return RequestContract(**values)  # type: ignore[arg-type]


def _policy(**changes: object) -> EgressPolicy:
    values: dict[str, object] = {
        "exact_hosts": frozenset({"api.example.com"}),
        "contracts": (_contract(),),
    }
    values.update(changes)
    return EgressPolicy(**values)  # type: ignore[arg-type]


def _request(**changes: object) -> EgressRequest:
    values: dict[str, object] = {
        "tool": "fetch_docs",
        "scheme": "https",
        "method": "GET",
        "hostname": "api.example.com",
        "path": "/v1/docs/guide",
    }
    values.update(changes)
    return EgressRequest(**values)  # type: ignore[arg-type]


def test_policy_is_deny_by_default() -> None:
    decision = check_request(EgressPolicy(), _request())

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == HOST_NOT_ALLOWED_RULE_ID


def test_exact_host_is_normalized_and_allowed() -> None:
    policy = _policy(exact_hosts=frozenset({"API.Example.COM."}))

    assert policy.exact_hosts == frozenset({"api.example.com"})
    assert check_host(policy, "api.example.com.").verdict == "ALLOW"


def test_suffix_rule_matches_children_but_not_parent_or_lookalikes() -> None:
    policy = EgressPolicy(suffix_hosts=frozenset({"example.com"}))

    assert check_host(policy, "api.example.com").verdict == "ALLOW"
    for hostname in ("example.com", "badexample.com", "example.com.evil.test"):
        decision = check_host(policy, hostname)
        assert decision.verdict == "BLOCK"
        assert decision.rule_id == HOST_NOT_ALLOWED_RULE_ID


def test_unicode_and_ascii_idna_forms_are_equivalent() -> None:
    policy = EgressPolicy(exact_hosts=frozenset({"BÜCHER.example"}))

    assert policy.exact_hosts == frozenset({"xn--bcher-kva.example"})
    assert check_host(policy, "bücher.example").verdict == "ALLOW"
    assert check_host(policy, "XN--BCHER-KVA.EXAMPLE.").verdict == "ALLOW"


@pytest.mark.parametrize(
    "hostname",
    (
        "",
        "bad..example",
        "-bad.example",
        "bad-.example",
        "bad_name.example",
        "example.com..",
    ),
)
def test_invalid_hostnames_fail_closed(hostname: str) -> None:
    decision = check_host(_policy(), hostname)

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == HOST_INVALID_RULE_ID
    if hostname:
        assert hostname not in decision.reason


@pytest.mark.parametrize(
    "hostname",
    ("localhost", "api.localhost", "127.0.0.1", "[::1]", "169.254.169.254"),
)
def test_localhost_and_ip_literals_are_prohibited(hostname: str) -> None:
    decision = check_host(_policy(), hostname)

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == HOST_PROHIBITED_RULE_ID
    assert hostname not in decision.reason


def test_invalid_or_prohibited_policy_rules_are_rejected_without_echo() -> None:
    for hostname in ("bad_name.example", "localhost", "127.0.0.1"):
        with pytest.raises(EgressPolicyError) as exc_info:
            EgressPolicy(exact_hosts=frozenset({hostname}))
        assert hostname not in str(exc_info.value)


def test_resolution_requires_every_cname_to_be_allowlisted() -> None:
    policy = EgressPolicy(
        exact_hosts=frozenset({"download.example.com", "edge.example.net"})
    )
    allowed = ResolverResult(
        requested_host="download.example.com",
        cname_chain=("edge.example.net",),
        addresses=frozenset({"93.184.216.34"}),
    )

    assert validate_resolution(policy, allowed).verdict == "ALLOW"

    denied = ResolverResult(
        requested_host="download.example.com",
        cname_chain=("attacker.invalid",),
        addresses=frozenset({"93.184.216.34"}),
    )
    decision = validate_resolution(policy, denied)
    assert decision.verdict == "BLOCK"
    assert decision.rule_id == HOST_NOT_ALLOWED_RULE_ID
    assert "attacker.invalid" not in decision.reason


@pytest.mark.parametrize(
    "address",
    (
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::",
    ),
)
def test_resolution_rejects_non_public_addresses(address: str) -> None:
    result = ResolverResult(
        requested_host="api.example.com",
        cname_chain=(),
        addresses=frozenset({"93.184.216.34", address}),
    )

    decision = validate_resolution(_policy(), result)
    assert decision.verdict == "BLOCK"
    assert decision.rule_id == RESOLUTION_PROHIBITED_RULE_ID
    assert address not in decision.reason


def test_resolution_rejects_empty_or_invalid_answers() -> None:
    for addresses in (frozenset(), frozenset({"not-an-address"})):
        result = ResolverResult("api.example.com", (), addresses)
        decision = validate_resolution(_policy(), result)
        assert decision.verdict == "BLOCK"
        assert decision.rule_id == RESOLUTION_INVALID_RULE_ID


def test_rebinding_rejects_changed_address_or_cname_chain() -> None:
    policy = EgressPolicy(
        exact_hosts=frozenset({"api.example.com", "edge.example.com"})
    )
    pinned = ResolverResult(
        "api.example.com",
        ("edge.example.com",),
        frozenset({"93.184.216.34"}),
    )
    same = ResolverResult(
        "API.EXAMPLE.COM.",
        ("EDGE.EXAMPLE.COM.",),
        frozenset({"93.184.216.34"}),
    )

    assert validate_resolution(policy, same, pinned=pinned).verdict == "ALLOW"

    for rebound in (
        ResolverResult(
            "api.example.com",
            ("edge.example.com",),
            frozenset({"8.8.8.8"}),
        ),
        ResolverResult("api.example.com", (), frozenset({"93.184.216.34"})),
    ):
        decision = validate_resolution(policy, rebound, pinned=pinned)
        assert decision.verdict == "BLOCK"
        assert decision.rule_id == DNS_REBINDING_RULE_ID


def test_contract_allows_only_exact_tool_scheme_method_and_path_boundary() -> None:
    policy = _policy()

    assert check_request(policy, _request()).verdict == "ALLOW"

    for request in (
        _request(tool="other_tool"),
        _request(scheme="http"),
        _request(method="POST"),
        _request(path="/v1/docs-private"),
        _request(path="relative/path"),
    ):
        decision = check_request(policy, request)
        assert decision.verdict == "BLOCK"
        assert decision.rule_id == REQUEST_CONTRACT_RULE_ID


@pytest.mark.parametrize(
    "path",
    (
        "/v1/docs/../admin",
        "/v1/docs/./guide",
        "/v1/docs/%2e%2e/admin",
        "/v1/docs//admin",
        "/v1/docs\\..\\admin",
        "/v1/docs/guide\nX-Injected: true",
        "/v1/docs/café",
    ),
)
def test_contract_rejects_ambiguous_or_noncanonical_request_paths(path: str) -> None:
    decision = check_request(_policy(), _request(path=path))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == REQUEST_CONTRACT_RULE_ID
    assert path not in decision.reason


@pytest.mark.parametrize(
    "prefix",
    (
        "/v1/docs/../admin",
        "/v1/docs/%2e%2e/admin",
        "/v1/docs//admin",
        "/v1/docs\\admin",
    ),
)
def test_contract_rejects_ambiguous_policy_path_prefixes(prefix: str) -> None:
    with pytest.raises(EgressPolicyError, match="path prefix is invalid"):
        _contract(path_prefixes=(prefix,))


def test_contract_denies_query_and_body_unless_explicitly_allowed() -> None:
    restrictive = _policy()
    assert check_request(restrictive, _request(has_query=True)).verdict == "BLOCK"
    assert check_request(restrictive, _request(has_body=True)).verdict == "BLOCK"

    permissive = _policy(contracts=(_contract(allow_query=True, allow_body=True),))
    assert check_request(permissive, _request(has_query=True, has_body=True)).verdict == "ALLOW"


def test_redirect_target_is_rechecked_against_host_and_contract() -> None:
    policy = _policy()

    assert check_request(policy, _request()).verdict == "ALLOW"
    denied_host = check_redirect(policy, _request(hostname="evil.example"))
    assert denied_host.verdict == "BLOCK"
    assert denied_host.rule_id == HOST_NOT_ALLOWED_RULE_ID

    denied_path = check_redirect(policy, _request(path="/collect/secret"))
    assert denied_path.verdict == "BLOCK"
    assert denied_path.rule_id == REQUEST_CONTRACT_RULE_ID


def test_policy_and_contract_are_immutable() -> None:
    policy = _policy()
    contract = policy.contracts[0]

    with pytest.raises(FrozenInstanceError):
        policy.exact_hosts = frozenset()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        contract.allow_body = True  # type: ignore[misc]


def test_normalize_hostname_rejects_ip_literals() -> None:
    with pytest.raises(EgressPolicyError):
        normalize_hostname("127.0.0.1")
