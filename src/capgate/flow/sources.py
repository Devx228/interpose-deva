from __future__ import annotations

import re
from enum import StrEnum


class DataSourceKind(StrEnum):
    """Taxonomy of data origins that source-to-sink deny rules may name.

    Distinct from `capgate.taint.sources.OriginKind`, which classifies *how much a value
    may be trusted*. This enum classifies *what kind of data it is*, which is what flow
    rules match on.
    """

    FILESYSTEM = "filesystem"
    DATABASE = "database"
    SECRETS = "secrets"
    PII = "pii"
    CUSTOMER_PII = "customer_pii"
    UNTRUSTED_WEB = "untrusted_web"
    EMAIL = "email"
    SLACK = "slack"
    TOOL_RESULT = "tool_result"
    MEMORY = "memory"


TAXONOMY_TAGS = frozenset(kind.value for kind in DataSourceKind)

_NAMESPACED_TAG = re.compile(r"[a-z][a-z0-9_-]*(?::[a-z0-9_.-]+)+\Z")


def is_valid_source_tag(tag: str) -> bool:
    """Return whether a source tag is a known taxonomy value or explicitly namespaced.

    A bare tag must name a `DataSourceKind`, because bare tags are exactly what
    source-to-sink deny pairs match on. An unrecognised bare tag such as `secret` would
    match no rule and silently disable the protection its author intended, with no error
    anywhere. Free-form provenance breadcrumbs remain available but must carry a
    namespace (`mcp:mail`, `agentdojo:workspace:send_email`) so that a misspelled
    taxonomy name can never be mistaken for a deliberate custom tag.
    """

    if ":" in tag:
        return _NAMESPACED_TAG.fullmatch(tag) is not None
    return tag in TAXONOMY_TAGS
