from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class PinStoreError(RuntimeError):
    """A sanitized persistent-pin storage failure."""


class PinStatus(StrEnum):
    NEW = "new"
    MATCH = "match"
    CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class PinCheck:
    status: PinStatus
    pinned_hash: str


class ToolPinStore(Protocol):
    def check_and_pin(self, server: str, tool: str, observed_hash: str) -> PinCheck: ...

    def get(self, server: str, tool: str) -> str | None: ...


class SqliteToolPinStore:
    """Atomic first-seen tool pins shared safely by independent proxy processes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise OSError
            if not path.exists():
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
            os.chmod(path, 0o600)
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tool_pins (
                        server TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        definition_hash TEXT NOT NULL,
                        PRIMARY KEY (server, tool)
                    )
                    """
                )
        except (OSError, sqlite3.Error):
            raise PinStoreError("tool pin store is unavailable") from None

    def check_and_pin(self, server: str, tool: str, observed_hash: str) -> PinCheck:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT definition_hash FROM tool_pins WHERE server = ? AND tool = ?",
                    (server, tool),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO tool_pins (server, tool, definition_hash) VALUES (?, ?, ?)",
                        (server, tool, observed_hash),
                    )
                    return PinCheck(PinStatus.NEW, observed_hash)
                pinned_hash = row[0]
                if not isinstance(pinned_hash, str):
                    raise sqlite3.DatabaseError
                status = PinStatus.MATCH if pinned_hash == observed_hash else PinStatus.CHANGED
                return PinCheck(status, pinned_hash)
        except sqlite3.Error:
            raise PinStoreError("tool pin store is unavailable") from None

    def get(self, server: str, tool: str) -> str | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT definition_hash FROM tool_pins WHERE server = ? AND tool = ?",
                    (server, tool),
                ).fetchone()
        except sqlite3.Error:
            raise PinStoreError("tool pin store is unavailable") from None
        if row is None:
            return None
        pinned_hash = row[0]
        if not isinstance(pinned_hash, str):
            raise PinStoreError("tool pin store is unavailable")
        return pinned_hash

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5.0)
