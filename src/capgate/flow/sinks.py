from __future__ import annotations

from enum import StrEnum


class SinkKind(StrEnum):
    NONE = "none"
    NETWORK_EXTERNAL = "network.external"
    EMAIL_EXTERNAL = "email.external"
    SLACK_EXTERNAL = "slack.external"
    SLACK_PUBLIC = "slack.public"
    SHELL_EXEC = "shell.exec"
    DB_WRITE = "db.write"
    GITHUB_PR = "github.pr"
    PAYMENT = "payment"
    FILE_WRITE = "file.write"


EXTERNAL_SINKS = frozenset(
    {
        SinkKind.NETWORK_EXTERNAL,
        SinkKind.EMAIL_EXTERNAL,
        SinkKind.SLACK_EXTERNAL,
        SinkKind.SLACK_PUBLIC,
        SinkKind.GITHUB_PR,
    }
)
