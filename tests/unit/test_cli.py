from __future__ import annotations

from pathlib import Path

import pytest

from capgate.cli import build_decision_pipeline
from capgate.config import ConfigError
from capgate.engine.context import AgentContext
from capgate.proxy.events import ToolCallEvent


def test_proxy_pipeline_is_optional_for_stage0() -> None:
    assert build_decision_pipeline(policy_file=None, tool_metadata_file=None) is None


def test_proxy_pipeline_requires_policy_and_metadata_together(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="provided together"):
        build_decision_pipeline(policy_file=tmp_path / "policy.yaml", tool_metadata_file=None)


def test_proxy_pipeline_loads_policy_and_metadata(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "agent: proxy-agent\ncan: [read:web]\ncannot: []\nrequires_approval: []\n",
        encoding="utf-8",
    )
    metadata = tmp_path / "tools.yaml"
    metadata.write_text(
        """
tools:
  search:
    capability: read:web
    confidentiality: public
    integrity: untrusted
    risk_class: trusted_direct
    source_tags: [untrusted_web]
""",
        encoding="utf-8",
    )

    pipeline = build_decision_pipeline(policy_file=policy, tool_metadata_file=metadata)

    assert pipeline is not None
    decision = pipeline.decide(
        AgentContext("session-1"),
        ToolCallEvent(
            session_id="session-1",
            server="test-server",
            tool="search",
            arguments={},
            arg_provenance={},
            request_id=1,
        ),
    )
    assert decision.verdict == "ALLOW"


def test_proxy_pipeline_hides_missing_policy_path(tmp_path: Path) -> None:
    missing = tmp_path / "SECRET-POLICY-NAME.yaml"

    with pytest.raises(ConfigError) as raised:
        build_decision_pipeline(
            policy_file=missing,
            tool_metadata_file=tmp_path / "tools.yaml",
        )

    assert str(missing) not in str(raised.value)
