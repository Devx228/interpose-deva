from __future__ import annotations

from enum import StrEnum


class SourceKind(StrEnum):
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
