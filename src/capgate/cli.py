from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence
from pathlib import Path

from capgate.config import CapgatePaths, ConfigError, load_deny_pairs, load_tool_metadata
from capgate.engine.pipeline import DecisionPipeline
from capgate.policy import PolicyError, load_policy
from capgate.proxy.server import run_stdio_proxy
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Verifier


def build_parser() -> argparse.ArgumentParser:
    defaults = CapgatePaths()
    parser = argparse.ArgumentParser(prog="capgate")
    subparsers = parser.add_subparsers(dest="command", required=True)

    proxy = subparsers.add_parser("proxy", help="Run the stdio JSON-RPC MCP mediation proxy.")
    proxy.add_argument("--receipt-log", type=Path, default=defaults.receipt_log)
    proxy.add_argument("--key-file", type=Path, default=defaults.private_key_file)
    proxy.add_argument("--public-key-file", type=Path, default=defaults.public_key_file)
    proxy.add_argument("--server-name", default="downstream")
    proxy.add_argument("--tool-pin-db", type=Path, default=defaults.tool_pin_db)
    proxy.add_argument("--policy-file", type=Path)
    proxy.add_argument("--tool-metadata-file", type=Path)
    proxy.add_argument(
        "--downstream",
        nargs=argparse.REMAINDER,
        required=True,
        help="Command used to start the downstream MCP server.",
    )

    replay = subparsers.add_parser("replay", help="Verify and print a receipt-log session.")
    replay.add_argument("session_id")
    replay.add_argument("--receipt-log", type=Path, default=defaults.receipt_log)
    replay.add_argument("--public-key-file", type=Path, default=defaults.public_key_file)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "proxy":
        downstream: list[str] = args.downstream
        if not downstream:
            parser.error("--downstream requires a command")
        try:
            decision_pipeline = build_decision_pipeline(
                policy_file=args.policy_file,
                tool_metadata_file=args.tool_metadata_file,
            )
        except (ConfigError, PolicyError) as exc:
            parser.error(str(exc))
        asyncio.run(
            run_stdio_proxy(
                downstream_command=downstream,
                receipt_log=args.receipt_log,
                private_key_file=args.key_file,
                public_key_file=args.public_key_file,
                server_name=args.server_name,
                decision_pipeline=decision_pipeline,
                tool_pin_db=args.tool_pin_db,
            )
        )
        return 0

    if args.command == "replay":
        verifier = Ed25519Verifier.from_public_key_file(args.public_key_file)
        report = replay_session(args.receipt_log, args.session_id, verifier)
        for line in report.to_lines():
            print(line)
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


def build_decision_pipeline(
    *,
    policy_file: Path | None,
    tool_metadata_file: Path | None,
) -> DecisionPipeline | None:
    if policy_file is None and tool_metadata_file is None:
        return None
    if policy_file is None or tool_metadata_file is None:
        raise ConfigError("--policy-file and --tool-metadata-file must be provided together")
    try:
        policy = load_policy(policy_file)
    except OSError:
        raise ConfigError("unable to read policy file") from None
    return DecisionPipeline(
        load_tool_metadata(tool_metadata_file),
        policy=policy,
        deny_pairs=load_deny_pairs(tool_metadata_file),
    )
