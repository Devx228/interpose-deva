from __future__ import annotations

from itertools import product

from capgate.taint.labels import BOTTOM_LABEL, Confidentiality, Integrity, Label
from capgate.taint.sources import SourceKind, classify_source


def _labels() -> tuple[Label, ...]:
    return tuple(
        Label(confidentiality, integrity, frozenset({confidentiality.value}))
        for confidentiality, integrity in product(Confidentiality, Integrity)
    )


def test_label_join_uses_most_restrictive_values_and_unions_tags() -> None:
    public_untrusted = Label(
        Confidentiality.PUBLIC,
        Integrity.UNTRUSTED,
        frozenset({"web"}),
    )
    secret_trusted = Label(
        Confidentiality.SECRET,
        Integrity.TRUSTED,
        frozenset({"secret-store"}),
    )

    joined = public_untrusted.join(secret_trusted)

    assert joined == Label(
        Confidentiality.SECRET,
        Integrity.UNTRUSTED,
        frozenset({"web", "secret-store"}),
    )


def test_label_join_laws_hold_exhaustively() -> None:
    labels = _labels()

    for left in labels:
        assert left.join(left) == left
        assert BOTTOM_LABEL.join(left) == left
        for right in labels:
            assert left.join(right) == right.join(left)
            for third in labels:
                assert left.join(right).join(third) == left.join(right.join(third))


def test_external_content_sources_are_untrusted_by_default() -> None:
    untrusted_sources = {
        SourceKind.MCP_TOOL_DESCRIPTION,
        SourceKind.MCP_TOOL_RESULT,
        SourceKind.WEB,
        SourceKind.EMAIL,
        SourceKind.FILE_UPLOAD,
        SourceKind.RAG,
        SourceKind.UNKNOWN,
    }

    assert all(
        classify_source(source).integrity is Integrity.UNTRUSTED
        for source in untrusted_sources
    )


def test_control_sources_are_trusted_only_when_explicitly_classified() -> None:
    trusted_sources = {
        SourceKind.DIRECT_USER_INSTRUCTION,
        SourceKind.SYSTEM_PROMPT,
        SourceKind.SIGNED_CONFIG,
    }

    assert all(
        classify_source(source).integrity is Integrity.TRUSTED for source in trusted_sources
    )


def test_source_classification_preserves_explicit_confidentiality_and_tags() -> None:
    label = classify_source(
        SourceKind.MCP_TOOL_RESULT,
        confidentiality=Confidentiality.SECRET,
        source_tags=("mcp:secrets",),
    )

    assert label == Label(
        Confidentiality.SECRET,
        Integrity.UNTRUSTED,
        frozenset({"mcp_tool_result", "mcp:secrets"}),
    )
