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


#: Sinks that can carry data *out* of the trust boundary. These are the exfiltration
#: channels the lethal-trifecta rule guards.
EXTERNAL_SINKS = frozenset(
    {
        SinkKind.NETWORK_EXTERNAL,
        SinkKind.EMAIL_EXTERNAL,
        SinkKind.SLACK_EXTERNAL,
        SinkKind.SLACK_PUBLIC,
        SinkKind.GITHUB_PR,
    }
)

#: Sinks that *change the world* rather than merely reveal it. Deleting records, writing
#: files, executing shell commands, and moving money are harmful even when no confidential
#: data is involved, so confidentiality-based rules cannot see them. Every sink other than
#: `NONE` qualifies: a sink is by definition a destination with security impact.
STATE_CHANGING_SINKS = frozenset(kind for kind in SinkKind if kind is not SinkKind.NONE)
