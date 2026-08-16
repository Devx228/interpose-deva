from __future__ import annotations

import os
import sys

import pytest


def credential_free_environment() -> dict[str, str]:
    """Return the smallest child environment that carries no ambient credentials.

    The offline demos assert they run with no API key, no ``.env``, and no inherited
    secrets, so they are launched with an explicit environment rather than the parent's.
    POSIX needs nothing at all. Windows needs ``SYSTEMROOT`` before ``import asyncio``
    can load its platform extension modules, so withholding it fails the demo for a
    reason that has nothing to do with security.
    """

    if sys.platform != "win32":
        return {}
    system_root = os.environ.get("SYSTEMROOT")
    return {"SYSTEMROOT": system_root} if system_root else {}


@pytest.fixture
def credential_free_env() -> dict[str, str]:
    return credential_free_environment()
