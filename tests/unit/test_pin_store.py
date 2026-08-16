from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from capgate.mcp_security.pinning import ToolPinRegistry
from capgate.mcp_security.store import PinStatus, PinStoreError, SqliteToolPinStore


def _definition(description: str) -> dict[str, object]:
    return {
        "name": "search",
        "description": description,
        "inputSchema": {"type": "object"},
    }


def test_sqlite_pins_survive_registry_restart(tmp_path: Path) -> None:
    path = tmp_path / "pins.sqlite3"
    first = ToolPinRegistry(SqliteToolPinStore(path))

    assert first.check("server", _definition("original")).verdict == "ALLOW"
    restarted = ToolPinRegistry(SqliteToolPinStore(path))

    assert restarted.check("server", _definition("original")).verdict == "ALLOW"
    changed = restarted.check("server", _definition("changed"))
    assert changed.verdict == "BLOCK"
    assert changed.rule_id == "mcp.tool_definition_changed"


def test_sqlite_first_seen_pin_is_atomic_across_threads(tmp_path: Path) -> None:
    store = SqliteToolPinStore(tmp_path / "pins.sqlite3")

    with ThreadPoolExecutor(max_workers=2) as executor:
        checks = list(
            executor.map(
                lambda digest: store.check_and_pin("server", "tool", digest),
                ("sha256:first", "sha256:second"),
            )
        )

    assert {check.status for check in checks} == {PinStatus.NEW, PinStatus.CHANGED}
    assert len({check.pinned_hash for check in checks}) == 1


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows has no POSIX permission bits; os.chmod only toggles the read-only flag",
)
def test_sqlite_store_uses_private_file_permissions(tmp_path: Path) -> None:
    path = tmp_path / "pins.sqlite3"

    SqliteToolPinStore(path)

    assert os.stat(path).st_mode & 0o777 == 0o600


def test_corrupt_store_error_is_sanitized(tmp_path: Path) -> None:
    path = tmp_path / "SECRET-pins.sqlite3"
    path.write_text("not sqlite", encoding="utf-8")

    with pytest.raises(PinStoreError) as raised:
        SqliteToolPinStore(path)

    assert str(raised.value) == "tool pin store is unavailable"
    assert "SECRET" not in str(raised.value)


def test_symlink_store_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.touch()
    link = tmp_path / "pins.sqlite3"
    try:
        link.symlink_to(target)
    except OSError:  # Windows requires administrator rights or developer mode
        pytest.skip("creating a symlink is not permitted in this environment")

    with pytest.raises(PinStoreError, match="unavailable"):
        SqliteToolPinStore(link)


class FailingStore:
    def check_and_pin(self, server: str, tool: str, observed_hash: str) -> object:
        _ = server, tool, observed_hash
        raise PinStoreError("sensitive storage failure")

    def get(self, server: str, tool: str) -> str | None:
        _ = server, tool
        raise PinStoreError("sensitive storage failure")


def test_registry_fails_closed_without_exposing_store_error() -> None:
    registry = ToolPinRegistry(FailingStore())  # type: ignore[arg-type]

    decision = registry.check("server", _definition("original"))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == "mcp.tool_pin_store_error"
    assert "sensitive" not in decision.reason
