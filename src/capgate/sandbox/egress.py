from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from capgate.engine.decision import Decision, Verdict

HOST_INVALID_RULE_ID = "sandbox.egress.host_invalid"
HOST_PROHIBITED_RULE_ID = "sandbox.egress.host_prohibited"
HOST_NOT_ALLOWED_RULE_ID = "sandbox.egress.host_not_allowed"
REQUEST_CONTRACT_RULE_ID = "sandbox.egress.request_contract"
RESOLUTION_INVALID_RULE_ID = "sandbox.egress.resolution_invalid"
RESOLUTION_PROHIBITED_RULE_ID = "sandbox.egress.resolution_prohibited"
DNS_REBINDING_RULE_ID = "sandbox.egress.dns_rebinding"
EGRESS_ALLOWED_RULE_ID = "sandbox.egress.allowed"

_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*\Z")
_METHOD = re.compile(r"[A-Z!#$%&'*+.^_`|~-]+\Z")
_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@/-]*\Z")


class EgressPolicyError(ValueError):
    """Raised when trusted egress-policy configuration is malformed."""


class _ProhibitedHost(EgressPolicyError):
    pass


def _decision(verdict: Verdict, reason: str, rule_id: str) -> Decision:
    return Decision(
        verdict=verdict,
        reason=reason,
        rule_id=rule_id,
        labels=frozenset(),
    )


def _canonical_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname or hostname != hostname.strip():
        raise EgressPolicyError("hostname is invalid")

    candidate = hostname
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate or candidate.endswith("."):
        raise EgressPolicyError("hostname is invalid")

    address_candidate = candidate
    if candidate.startswith("[") and candidate.endswith("]"):
        address_candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(address_candidate)
    except ValueError:
        if "[" in candidate or "]" in candidate:
            raise EgressPolicyError("hostname is invalid") from None
    else:
        raise _ProhibitedHost("IP literals are prohibited")

    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise EgressPolicyError("hostname is invalid") from None

    if normalized == "localhost" or normalized.endswith(".localhost"):
        raise _ProhibitedHost("localhost is prohibited")
    if len(normalized) > 253:
        raise EgressPolicyError("hostname is invalid")
    labels = normalized.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise EgressPolicyError("hostname is invalid")
    return normalized


def normalize_hostname(hostname: str) -> str:
    """Return a lower-case ASCII IDNA hostname without its final root dot."""

    return _canonical_hostname(hostname)


def _is_canonical_path(path: str) -> bool:
    if not _PATH.fullmatch(path) or "//" in path:
        return False
    return all(segment not in {".", ".."} for segment in path.split("/"))


@dataclass(frozen=True)
class RequestContract:
    """The HTTP request shapes one exact tool may issue through the broker."""

    tool: str
    schemes: frozenset[str] = frozenset()
    methods: frozenset[str] = frozenset()
    path_prefixes: tuple[str, ...] = ()
    allow_query: bool = False
    allow_body: bool = False

    def __post_init__(self) -> None:
        if not self.tool or self.tool != self.tool.strip():
            raise EgressPolicyError("request contract tool is invalid")

        schemes = frozenset(scheme.lower() for scheme in self.schemes)
        methods = frozenset(method.upper() for method in self.methods)
        if any(not _SCHEME.fullmatch(scheme) for scheme in schemes):
            raise EgressPolicyError("request contract scheme is invalid")
        if any(not _METHOD.fullmatch(method) for method in methods):
            raise EgressPolicyError("request contract method is invalid")
        if any(not _is_canonical_path(prefix) for prefix in self.path_prefixes):
            raise EgressPolicyError("request contract path prefix is invalid")
        if not isinstance(self.allow_query, bool) or not isinstance(self.allow_body, bool):
            raise EgressPolicyError("request contract flags are invalid")

        object.__setattr__(self, "schemes", schemes)
        object.__setattr__(self, "methods", methods)
        object.__setattr__(self, "path_prefixes", tuple(sorted(set(self.path_prefixes))))


@dataclass(frozen=True)
class EgressPolicy:
    """Immutable host allowlist and per-tool request contracts; empty denies all."""

    exact_hosts: frozenset[str] = frozenset()
    suffix_hosts: frozenset[str] = frozenset()
    contracts: tuple[RequestContract, ...] = ()

    def __post_init__(self) -> None:
        try:
            exact_hosts = frozenset(_canonical_hostname(host) for host in self.exact_hosts)
            suffix_hosts = frozenset(
                _canonical_hostname(host) for host in self.suffix_hosts
            )
        except EgressPolicyError:
            raise EgressPolicyError(
                "egress policy contains an invalid or prohibited hostname"
            ) from None

        contracts = tuple(sorted(self.contracts, key=lambda contract: contract.tool))
        if len({contract.tool for contract in contracts}) != len(contracts):
            raise EgressPolicyError("egress policy contains duplicate tool contracts")
        object.__setattr__(self, "exact_hosts", exact_hosts)
        object.__setattr__(self, "suffix_hosts", suffix_hosts)
        object.__setattr__(self, "contracts", contracts)


@dataclass(frozen=True)
class EgressRequest:
    tool: str
    scheme: str
    method: str
    hostname: str
    path: str
    has_query: bool = False
    has_body: bool = False


@dataclass(frozen=True)
class ResolverResult:
    requested_host: str
    cname_chain: tuple[str, ...]
    addresses: frozenset[str]


@dataclass(frozen=True)
class _CanonicalResolution:
    requested_host: str
    cname_chain: tuple[str, ...]
    addresses: frozenset[str]


def check_host(policy: EgressPolicy, hostname: str) -> Decision:
    try:
        normalized = _canonical_hostname(hostname)
    except _ProhibitedHost:
        return _decision(
            "BLOCK",
            "destination hostname is prohibited",
            HOST_PROHIBITED_RULE_ID,
        )
    except EgressPolicyError:
        return _decision(
            "BLOCK", "destination hostname is invalid", HOST_INVALID_RULE_ID
        )

    if normalized in policy.exact_hosts or any(
        normalized.endswith(f".{suffix}") for suffix in policy.suffix_hosts
    ):
        return _decision(
            "ALLOW", "destination hostname is explicitly allowed", EGRESS_ALLOWED_RULE_ID
        )
    return _decision(
        "BLOCK",
        "destination hostname is not allowed by egress policy",
        HOST_NOT_ALLOWED_RULE_ID,
    )


def _contract_for(policy: EgressPolicy, tool: str) -> RequestContract | None:
    return next((contract for contract in policy.contracts if contract.tool == tool), None)


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return path.startswith("/")
    normalized_prefix = prefix.rstrip("/")
    return path == normalized_prefix or path.startswith(f"{normalized_prefix}/")


def check_request(policy: EgressPolicy, request: EgressRequest) -> Decision:
    host_decision = check_host(policy, request.hostname)
    if host_decision.verdict != "ALLOW":
        return host_decision

    contract = _contract_for(policy, request.tool)
    request_shape_valid = (
        contract is not None
        and request.scheme == request.scheme.lower()
        and request.scheme in contract.schemes
        and request.method == request.method.upper()
        and request.method in contract.methods
        and _is_canonical_path(request.path)
        and any(_path_matches(request.path, prefix) for prefix in contract.path_prefixes)
        and isinstance(request.has_query, bool)
        and isinstance(request.has_body, bool)
        and (contract.allow_query or not request.has_query)
        and (contract.allow_body or not request.has_body)
    )
    if not request_shape_valid:
        return _decision(
            "BLOCK",
            "request does not satisfy the tool egress contract",
            REQUEST_CONTRACT_RULE_ID,
        )
    return _decision(
        "ALLOW",
        "request satisfies host policy and tool egress contract",
        EGRESS_ALLOWED_RULE_ID,
    )


def check_redirect(policy: EgressPolicy, redirected_request: EgressRequest) -> Decision:
    """Re-run all host and request-contract checks for one redirect target."""

    return check_request(policy, redirected_request)


def _canonical_resolution(
    policy: EgressPolicy, result: ResolverResult
) -> tuple[Decision, _CanonicalResolution | None]:
    raw_names = (result.requested_host, *result.cname_chain)
    normalized_names: list[str] = []
    for hostname in raw_names:
        decision = check_host(policy, hostname)
        if decision.verdict != "ALLOW":
            return decision, None
        normalized_names.append(_canonical_hostname(hostname))

    if len(set(normalized_names)) != len(normalized_names) or not result.addresses:
        return (
            _decision(
                "BLOCK",
                "resolver result is invalid",
                RESOLUTION_INVALID_RULE_ID,
            ),
            None,
        )

    addresses: set[str] = set()
    for raw_address in result.addresses:
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            return (
                _decision(
                    "BLOCK",
                    "resolver result is invalid",
                    RESOLUTION_INVALID_RULE_ID,
                ),
                None,
            )
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or not address.is_global
        ):
            return (
                _decision(
                    "BLOCK",
                    "resolver result contains a prohibited address",
                    RESOLUTION_PROHIBITED_RULE_ID,
                ),
                None,
            )
        addresses.add(str(address))

    return (
        _decision(
            "ALLOW",
            "resolver names and addresses satisfy egress policy",
            EGRESS_ALLOWED_RULE_ID,
        ),
        _CanonicalResolution(
            requested_host=normalized_names[0],
            cname_chain=tuple(normalized_names[1:]),
            addresses=frozenset(addresses),
        ),
    )


def validate_resolution(
    policy: EgressPolicy,
    result: ResolverResult,
    *,
    pinned: ResolverResult | None = None,
) -> Decision:
    """Validate all DNS evidence and reject any change from a pinned answer."""

    decision, canonical = _canonical_resolution(policy, result)
    if canonical is None:
        return decision
    if pinned is None:
        return decision

    pinned_decision, canonical_pin = _canonical_resolution(policy, pinned)
    if canonical_pin is None:
        return pinned_decision
    if canonical != canonical_pin:
        return _decision(
            "BLOCK",
            "resolver answer changed after destination approval",
            DNS_REBINDING_RULE_ID,
        )
    return decision
