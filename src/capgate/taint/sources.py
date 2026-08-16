from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from capgate.taint.labels import Confidentiality, Integrity, Label


class OriginKind(StrEnum):
    DIRECT_USER_INSTRUCTION = "direct_user_instruction"
    SYSTEM_PROMPT = "system_prompt"
    SIGNED_CONFIG = "signed_config"
    MCP_TOOL_DESCRIPTION = "mcp_tool_description"
    MCP_TOOL_RESULT = "mcp_tool_result"
    WEB = "web"
    EMAIL = "email"
    FILE_UPLOAD = "file_upload"
    RAG = "rag"
    UNKNOWN = "unknown"


_TRUSTED_SOURCES = frozenset(
    {
        OriginKind.DIRECT_USER_INSTRUCTION,
        OriginKind.SYSTEM_PROMPT,
        OriginKind.SIGNED_CONFIG,
    }
)


def classify_source(
    source: OriginKind,
    *,
    confidentiality: Confidentiality = Confidentiality.PUBLIC,
    source_tags: Iterable[str] = (),
) -> Label:
    integrity = Integrity.TRUSTED if source in _TRUSTED_SOURCES else Integrity.UNTRUSTED
    return Label(
        confidentiality=confidentiality,
        integrity=integrity,
        source_tags=frozenset({source.value, *source_tags}),
    )


UNKNOWN_LABEL = classify_source(OriginKind.UNKNOWN)
