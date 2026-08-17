from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from capgate.benchmark import attack_success_rate
from capgate.config import CapgatePaths
from capgate.engine.context import AgentContext
from capgate.engine.decision import STAGE0_ALLOW, Decision
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.policy.model import CapabilityPattern, Policy
from capgate.proxy.events import JsonObject, JsonValue, ToolCallEvent, ToolResultEvent
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import Confidentiality
from capgate.taint.sources import OriginKind, classify_source

Mode = Literal["undefended", "capgate"]
PipelineKind = Literal["agentdojo", "ground-truth"]
EnforcementMode = Literal["none", "stage0", "stage1"]
DEFAULT_MODEL = "gpt-4o-2024-05-13"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_GIT_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class AgentDojoReport:
    mode: Mode
    status: Literal["blocked", "completed"]
    pipeline: PipelineKind
    model: str
    benchmark_version: str
    suite: str
    attack: str | None
    user_tasks: list[str] | None
    injection_tasks: list[str] | None
    utility: float | None
    asr: float | None
    utility_cases: int
    security_cases: int
    mediated_tool_calls: int
    generated_at: str
    note: str
    mediation: str = "none"
    receipt_session_ids: tuple[str, ...] = ()
    observed_tool_calls: int = 0
    verified_receipts: int = 0
    receipt_chain_valid: bool | None = None
    enforcement: EnforcementMode = "none"
    allowed_tool_calls: int = 0
    blocked_tool_calls: int = 0
    command: tuple[str, ...] = ()
    agentdojo_version: str | None = None
    code_revision: str | None = None


@dataclass
class AuditState:
    receipt_log: Path
    signer: Ed25519Signer
    session_ids: list[str]
    enforcement: EnforcementMode
    observed_tool_calls: int = 0
    mediated_tool_calls: int = 0
    allowed_tool_calls: int = 0
    blocked_tool_calls: int = 0


def run_agentdojo(
    *,
    mode: Mode,
    pipeline_kind: PipelineKind,
    benchmark_version: str,
    suite_name: str,
    attack_name: str,
    model: str,
    user_tasks: Sequence[str] | None,
    injection_tasks: Sequence[str] | None,
    logdir: Path | None,
    force_rerun: bool,
    receipt_log: Path,
    private_key_file: Path,
    public_key_file: Path,
    enforcement: Literal["stage0", "stage1"],
) -> AgentDojoReport:
    try:
        import openai
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
        from agentdojo.attacks.attack_registry import ATTACKS
        from agentdojo.benchmark import (
            aggregate_results,
            benchmark_suite_with_injections,
            benchmark_suite_without_injections,
        )
        from agentdojo.logging import OutputLogger
        from agentdojo.task_suite.load_suites import get_suite
        from dotenv import load_dotenv
    except ImportError as exc:
        return AgentDojoReport(
            mode=mode,
            status="blocked",
            pipeline=pipeline_kind,
            model=model,
            benchmark_version=benchmark_version,
            suite=suite_name,
            attack=attack_name,
            user_tasks=_list_or_none(user_tasks),
            injection_tasks=_list_or_none(injection_tasks),
            utility=None,
            asr=None,
            utility_cases=0,
            security_cases=0,
            mediated_tool_calls=0,
            generated_at=_now(),
            note=f"AgentDojo import failed: {exc}",
        )

    suite = get_suite(benchmark_version, suite_name)
    selected_user_tasks = _list_or_none(user_tasks)
    selected_injection_tasks = _list_or_none(injection_tasks)
    if logdir is None:
        logdir = Path("bench/reports/agentdojo-runs")
    if pipeline_kind == "ground-truth":
        if selected_user_tasks is None:
            selected_user_tasks = [next(iter(suite.user_tasks))]
        first_task = suite.get_user_task_by_id(selected_user_tasks[0])
        pipeline = GroundTruthPipeline(first_task)
        pipeline.name = "ground-truth"
    else:
        load_dotenv(".env")
        if model == DEFAULT_MODEL:
            model = os.getenv("CAPGATE_AGENTDOJO_MODEL", model)
        missing = _missing_required_env_for_model(model, base_url=os.getenv("OPENAI_BASE_URL"))
        if missing:
            return AgentDojoReport(
                mode=mode,
                status="blocked",
                pipeline=pipeline_kind,
                model=model,
                benchmark_version=benchmark_version,
                suite=suite_name,
                attack=attack_name,
                user_tasks=selected_user_tasks,
                injection_tasks=selected_injection_tasks,
                utility=None,
                asr=None,
                utility_cases=0,
                security_cases=0,
                mediated_tool_calls=0,
                generated_at=_now(),
                note=f"Missing required environment for model {model}: {', '.join(missing)}",
            )
        if _is_builtin_agentdojo_model(model):
            pipeline = AgentPipeline.from_config(
                PipelineConfig(
                    llm=model,
                    model_id=None,
                    defense=None,
                    system_message_name=None,
                    system_message=None,
                )
            )
        else:
            base_url = os.getenv("OPENAI_BASE_URL")
            client_kwargs: dict[str, str] = {"api_key": os.environ["OPENAI_API_KEY"]}
            if base_url is not None:
                client_kwargs["base_url"] = base_url
            pipeline = _build_openai_compatible_pipeline(
                openai_module=openai,
                model=model,
                client_kwargs=client_kwargs,
            )
            pipeline.name = _filesystem_safe_name(model)

    audit_state: AuditState | None = None
    if mode == "capgate":
        decision_pipeline = (
            _stage1_pipeline(
                suite_name=suite_name,
                tool_names=tuple(tool.name for tool in suite.tools),
            )
            if enforcement == "stage1"
            else None
        )
        pipeline, audit_state = _wrap_with_capgate_audit(
            pipeline=pipeline,
            receipt_log=receipt_log,
            private_key_file=private_key_file,
            public_key_file=public_key_file,
            server_name=f"agentdojo:{suite_name}",
            enforcement=enforcement,
            decision_pipeline=decision_pipeline,
        )
        if enforcement == "stage1":
            note_prefix = (
                "Stage 1 deterministic source-to-sink enforcement via the AgentDojo runtime "
                "mediation path; every decision has a replay-verified receipt."
            )
        else:
            note_prefix = (
                "Stage 0 pass-through via the AgentDojo runtime mediation path; tool execution "
                "is delegated unchanged and every observed call has a replay-verified receipt."
            )
    else:
        note_prefix = "Undefended AgentDojo run."

    if attack_name == "none":
        with OutputLogger(str(logdir)):
            results = benchmark_suite_without_injections(
                pipeline,
                suite,
                logdir=logdir,
                force_rerun=force_rerun or mode == "capgate",
                user_tasks=selected_user_tasks,
                benchmark_version=benchmark_version,
            )
        utility = aggregate_results([results["utility_results"]])
        return _finalize_audit(
            AgentDojoReport(
                mode=mode,
                status="completed",
                pipeline=pipeline_kind,
                model="ground-truth" if pipeline_kind == "ground-truth" else model,
                benchmark_version=benchmark_version,
                suite=suite_name,
                attack=None,
                user_tasks=selected_user_tasks,
                injection_tasks=None,
                utility=utility,
                asr=None,
                utility_cases=len(results["utility_results"]),
                security_cases=0,
                mediated_tool_calls=_mediated_tool_calls(audit_state),
                generated_at=_now(),
                note=note_prefix,
            ),
            audit_state,
        )

    attack_cls = ATTACKS[attack_name]
    attack = attack_cls(suite, pipeline)
    with OutputLogger(str(logdir)):
        results = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack,
            logdir=logdir,
            force_rerun=force_rerun or mode == "capgate",
            user_tasks=selected_user_tasks,
            injection_tasks=selected_injection_tasks,
            benchmark_version=benchmark_version,
        )
    utility = aggregate_results([results["utility_results"]])
    asr = attack_success_rate(results["security_results"])
    return _finalize_audit(
        AgentDojoReport(
            mode=mode,
            status="completed",
            pipeline=pipeline_kind,
            model="ground-truth" if pipeline_kind == "ground-truth" else model,
            benchmark_version=benchmark_version,
            suite=suite_name,
            attack=attack_name,
            user_tasks=selected_user_tasks,
            injection_tasks=selected_injection_tasks,
            utility=utility,
            asr=asr,
            utility_cases=len(results["utility_results"]),
            security_cases=len(results["security_results"]),
            mediated_tool_calls=_mediated_tool_calls(audit_state),
            generated_at=_now(),
            note=note_prefix,
        ),
        audit_state,
    )


def write_report(report: AgentDojoReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(asdict(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    paths = CapgatePaths()
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["undefended", "capgate"], required=True)
    parser.add_argument("--enforcement", choices=["stage0", "stage1"], default="stage0")
    parser.add_argument("--pipeline", choices=["agentdojo", "ground-truth"], default="agentdojo")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--attack", default="direct")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--user-task", action="append", dest="user_tasks")
    parser.add_argument("--injection-task", action="append", dest="injection_tasks")
    parser.add_argument("--logdir", type=Path)
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument("--receipt-log", type=Path, default=paths.receipt_log)
    parser.add_argument("--key-file", type=Path, default=paths.private_key_file)
    parser.add_argument("--public-key-file", type=Path, default=paths.public_key_file)
    parser.add_argument("--out", type=Path, required=True)
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_argv)
    report = run_agentdojo(
        mode=args.mode,
        pipeline_kind=args.pipeline,
        benchmark_version=args.benchmark_version,
        suite_name=args.suite,
        attack_name=args.attack,
        model=args.model,
        user_tasks=args.user_tasks,
        injection_tasks=args.injection_tasks,
        logdir=args.logdir,
        force_rerun=args.force_rerun,
        receipt_log=args.receipt_log,
        private_key_file=args.key_file,
        public_key_file=args.public_key_file,
        enforcement=args.enforcement,
    )
    report = replace(
        report,
        command=(sys.executable, "bench/agentdojo_runner.py", *raw_argv),
        agentdojo_version=_package_version("agentdojo"),
        code_revision=_clean_git_revision(),
    )
    write_report(report, args.out)
    print(json.dumps(asdict(report), sort_keys=True))
    return 0 if report.status == "completed" else 2


_UNSAFE_NAME_CHARS = re.compile(r'[<>:"/\\|?*]')


def _filesystem_safe_name(name: str) -> str:
    """Return a pipeline name usable as a directory component on every platform.

    AgentDojo writes results to `<logdir>/<pipeline.name>/...`, so a model identifier like
    `qwen2.5:7b` becomes an invalid path on Windows. Only the on-disk name is sanitised;
    the model string sent to the provider is untouched.
    """

    return _UNSAFE_NAME_CHARS.sub("-", name)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _list_or_none(values: Sequence[str] | None) -> list[str] | None:
    if values is None:
        return None
    return list(values)


def _mediated_tool_calls(audit_state: AuditState | None) -> int:
    if audit_state is None:
        return 0
    return audit_state.mediated_tool_calls


def _finalize_audit(
    report: AgentDojoReport,
    audit_state: AuditState | None,
) -> AgentDojoReport:
    if audit_state is None:
        return report

    verified_receipts = 0
    verifier = audit_state.signer.verifier()
    for session_id in audit_state.session_ids:
        replay = replay_session(audit_state.receipt_log, session_id, verifier)
        verified_receipts += len(replay.receipts)

    if verified_receipts != audit_state.observed_tool_calls:
        raise RuntimeError(
            "CapGate audit mismatch: "
            f"observed {audit_state.observed_tool_calls} tool calls but verified "
            f"{verified_receipts} receipts"
        )
    if audit_state.mediated_tool_calls != audit_state.observed_tool_calls:
        raise RuntimeError(
            "CapGate mediation mismatch: "
            f"observed {audit_state.observed_tool_calls} tool calls but wrote "
            f"{audit_state.mediated_tool_calls} receipts"
        )

    return replace(
        report,
        mediation="agentdojo-runtime",
        receipt_session_ids=tuple(audit_state.session_ids),
        observed_tool_calls=audit_state.observed_tool_calls,
        verified_receipts=verified_receipts,
        receipt_chain_valid=True,
        enforcement=audit_state.enforcement,
        allowed_tool_calls=audit_state.allowed_tool_calls,
        blocked_tool_calls=audit_state.blocked_tool_calls,
    )


_WORKSPACE_INTERNAL_RESULT_TOOLS = frozenset(
    {
        "add_calendar_event_participants",
        "append_to_file",
        "cancel_calendar_event",
        "create_calendar_event",
        "create_file",
        "delete_email",
        "delete_file",
        "get_day_calendar_events",
        "get_draft_emails",
        "get_file_by_id",
        "get_received_emails",
        "get_sent_emails",
        "get_unread_emails",
        "list_files",
        "reschedule_calendar_event",
        "search_calendar_events",
        "search_contacts_by_email",
        "search_contacts_by_name",
        "search_emails",
        "search_files",
        "search_files_by_filename",
        "send_email",
        "share_file",
    }
)
_WORKSPACE_PUBLIC_RESULT_TOOLS = frozenset({"get_current_day"})


def _stage1_pipeline(*, suite_name: str, tool_names: tuple[str, ...]) -> DecisionPipeline:
    if suite_name != "workspace":
        raise ValueError("Stage 1 benchmark metadata is currently defined only for workspace")
    known_tools = _WORKSPACE_INTERNAL_RESULT_TOOLS | _WORKSPACE_PUBLIC_RESULT_TOOLS
    unclassified_tools = set(tool_names) - known_tools
    if unclassified_tools:
        names = ", ".join(sorted(unclassified_tools))
        raise ValueError(f"workspace tools lack Stage 1 security metadata: {names}")

    metadata: dict[str, ToolMetadata] = {}
    capabilities: list[CapabilityPattern] = []
    for tool_name in tool_names:
        confidentiality = (
            Confidentiality.INTERNAL
            if tool_name in _WORKSPACE_INTERNAL_RESULT_TOOLS
            else Confidentiality.PUBLIC
        )
        sink = SinkKind.NONE
        if tool_name == "send_email":
            sink = SinkKind.EMAIL_EXTERNAL
        elif tool_name == "share_file":
            sink = SinkKind.NETWORK_EXTERNAL
        capability = _workspace_capability(tool_name)
        capabilities.append(CapabilityPattern.parse(capability))
        metadata[tool_name] = ToolMetadata(
            result_label=classify_source(
                OriginKind.MCP_TOOL_RESULT,
                confidentiality=confidentiality,
                source_tags=(f"agentdojo:{suite_name}:{tool_name}",),
            ),
            risk_class=RiskClass.TRUSTED_DIRECT,
            sink=sink,
            capability=capability,
        )
    return DecisionPipeline(
        metadata,
        policy=Policy(
            agent="agentdojo-workspace",
            can=tuple(capabilities),
            cannot=(),
            requires_approval=(),
        ),
    )


def _workspace_capability(tool_name: str) -> str:
    if tool_name.startswith(("get_", "list_", "search_")):
        action = "read"
    elif tool_name.startswith("delete_") or tool_name.startswith("cancel_"):
        action = "delete"
    elif tool_name in {"send_email", "share_file"}:
        action = "send"
    else:
        action = "write"
    return f"{action}:workspace.{tool_name}"


def _wrap_with_capgate_audit(
    *,
    pipeline: Any,
    receipt_log: Path,
    private_key_file: Path,
    public_key_file: Path,
    server_name: str,
    enforcement: Literal["stage0", "stage1"],
    decision_pipeline: DecisionPipeline | None,
) -> tuple[Any, AuditState]:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import FunctionsRuntime

    signer = Ed25519Signer.load_or_create(private_key_file, public_key_file)
    writer = ReceiptWriter(store=JsonlReceiptStore(receipt_log), signer=signer)
    audit_state = AuditState(
        receipt_log=receipt_log,
        signer=signer,
        session_ids=[],
        enforcement=enforcement,
    )

    class AuditedRuntime(FunctionsRuntime):
        def __init__(
            self,
            runtime: Any,
            session_id: str,
            context: AgentContext,
        ) -> None:
            super().__init__(())
            self._runtime = runtime
            self.functions = runtime.functions
            self._session_id = session_id
            self._context = context

        def run_function(
            self,
            env: Any,
            function: str,
            kwargs: Mapping[str, Any],
            raise_on_error: bool = False,
        ) -> Any:
            audit_state.observed_tool_calls += 1
            call_event = ToolCallEvent(
                session_id=self._session_id,
                server=server_name,
                tool=function,
                arguments=_json_object(kwargs),
                arg_provenance={},
                request_id=audit_state.observed_tool_calls,
            )
            decision = (
                decision_pipeline.decide(self._context, call_event)
                if decision_pipeline is not None
                else STAGE0_ALLOW
            )
            if decision.verdict != "ALLOW":
                error = f"CapGate blocked tool call ({decision.rule_id}): {decision.reason}"
                _write_audited_result(
                    writer=writer,
                    audit_state=audit_state,
                    call_event=call_event,
                    result={"error": error},
                    decision=decision,
                )
                return "", error
            try:
                result, error = self._runtime.run_function(
                    env,
                    function,
                    kwargs,
                    raise_on_error,
                )
            except Exception as exc:
                _write_audited_result(
                    writer=writer,
                    audit_state=audit_state,
                    call_event=call_event,
                    result={"error_type": type(exc).__name__},
                    decision=decision,
                )
                raise

            audited_result: JsonValue = _json_value(result)
            if error is not None:
                audited_result = {"result": audited_result, "error": error}
            result_event = _write_audited_result(
                writer=writer,
                audit_state=audit_state,
                call_event=call_event,
                result=audited_result,
                decision=decision,
            )
            if decision_pipeline is not None:
                decision_pipeline.observe_result(self._context, call_event, result_event)
            return result, error

    class AuditedPipeline(BasePipelineElement):
        delegate_name = getattr(pipeline, "name", None)
        name = (
            f"{delegate_name}-capgate-{enforcement}"
            if delegate_name is not None
            else f"capgate-{enforcement}"
        )

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any = None,
            messages: Sequence[Any] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> Any:
            session_id = str(uuid.uuid4())
            audit_state.session_ids.append(session_id)
            context = AgentContext(session_id=session_id)
            audited_runtime = AuditedRuntime(runtime, session_id, context)
            query, _, env, messages, extra_args = pipeline.query(
                query,
                audited_runtime,
                env,
                messages,
                {} if extra_args is None else extra_args,
            )
            return query, runtime, env, messages, extra_args

    return AuditedPipeline(), audit_state


def _write_audited_result(
    *,
    writer: ReceiptWriter,
    audit_state: AuditState,
    call_event: ToolCallEvent,
    result: JsonValue,
    decision: Decision,
) -> ToolResultEvent:
    result_event = ToolResultEvent(
        session_id=call_event.session_id,
        server=call_event.server,
        tool=call_event.tool,
        result=result,
        request_id=call_event.request_id,
    )
    writer.write_tool_call(
        call_event=call_event,
        result_event=result_event,
        decision=decision,
    )
    audit_state.mediated_tool_calls += 1
    if decision.verdict == "BLOCK":
        audit_state.blocked_tool_calls += 1
    else:
        audit_state.allowed_tool_calls += 1
    return result_event


def _json_object(value: Mapping[str, Any]) -> JsonObject:
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_value(value: Any) -> JsonValue:
    from pydantic import BaseModel

    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump())
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, bytes):
        return [_json_value(item) for item in value]
    return str(value)


def _package_version(package: str) -> str | None:
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def _clean_git_revision(repo_root: Path = _REPO_ROOT) -> str | None:
    git_executable = shutil.which("git")
    if git_executable is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, trusted local Git executable
            [
                git_executable,
                "--no-optional-locks",
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            cwd=repo_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None

    revision: str | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("# branch.oid "):
            revision = line.removeprefix("# branch.oid ")
        elif not line.startswith("# "):
            return None
    if revision is None or len(revision) not in {40, 64}:
        return None
    if any(character not in "0123456789abcdef" for character in revision):
        return None
    return revision


def _missing_required_env_for_model(model: str, *, base_url: str | None) -> list[str]:
    if base_url is not None:
        return [] if os.getenv("OPENAI_API_KEY") else ["OPENAI_API_KEY"]
    checks: dict[str, list[str]] = {
        "gpt": ["OPENAI_API_KEY"],
        "o1": ["OPENAI_API_KEY"],
        "o3": ["OPENAI_API_KEY"],
        "o4": ["OPENAI_API_KEY"],
        "claude": ["ANTHROPIC_API_KEY"],
        "command": ["COHERE_API_KEY"],
        "gemini": ["GCP_PROJECT", "GCP_LOCATION"],
        "llama": ["TOGETHER_API_KEY"],
    }
    lowered = model.lower()
    required: list[str] = []
    for prefix, env_vars in checks.items():
        if lowered.startswith(prefix):
            required = env_vars
            break
    return [env_var for env_var in required if not os.getenv(env_var)]


def _is_builtin_agentdojo_model(model: str) -> bool:
    try:
        from agentdojo.models import ModelsEnum
    except ImportError:
        return False
    return model in {value for value in ModelsEnum}


def _build_openai_compatible_pipeline(
    *,
    openai_module: Any,
    model: str,
    client_kwargs: dict[str, str],
) -> Any:
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    from agentdojo.functions_runtime import EmptyEnv, FunctionCall
    from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

    class OpenAICompatibleLLM(BasePipelineElement):
        name = _filesystem_safe_name(model)

        def __init__(self) -> None:
            self.client = openai_module.OpenAI(**client_kwargs)

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any = None,
            messages: Sequence[Any] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
            if env is None:
                env = EmptyEnv()
            if extra_args is None:
                extra_args = {}
            request: dict[str, Any] = {
                "model": model,
                "messages": [_message_to_openai_compatible(message) for message in messages],
                "temperature": 0,
            }
            tools = [_function_to_openai_tool(tool) for tool in runtime.functions.values()]
            if tools:
                request["tools"] = tools
                request["tool_choice"] = "auto"
            completion = self.client.chat.completions.create(**request)
            message = completion.choices[0].message
            tool_calls = None
            if message.tool_calls:
                tool_calls = [
                    FunctionCall(
                        function=tool_call.function.name,
                        args=json.loads(tool_call.function.arguments or "{}"),
                        id=tool_call.id,
                    )
                    for tool_call in message.tool_calls
                ]
            content = None
            if message.content is not None:
                content = [text_content_block_from_string(message.content)]
            assistant_message = ChatAssistantMessage(
                role="assistant",
                content=content,
                tool_calls=tool_calls,
            )
            return query, runtime, env, [*messages, assistant_message], extra_args

    llm = OpenAICompatibleLLM()
    return AgentPipeline(
        [
            SystemMessage("You are a helpful AI assistant."),
            InitQuery(),
            llm,
            ToolsExecutionLoop([ToolsExecutor(), llm]),
        ]
    )


def _message_to_openai_compatible(message: Any) -> dict[str, Any]:
    from agentdojo.types import get_text_content_as_str

    role = message["role"]
    if role in {"system", "user"}:
        return {"role": role, "content": get_text_content_as_str(message["content"])}
    if role == "assistant":
        converted: dict[str, Any] = {
            "role": "assistant",
            "content": get_text_content_as_str(message["content"]) if message["content"] else "",
        }
        if message["tool_calls"]:
            converted["tool_calls"] = [
                {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function,
                        "arguments": json.dumps(tool_call.args),
                    },
                }
                for tool_call in message["tool_calls"]
            ]
        return converted
    if role == "tool":
        return {
            "role": "tool",
            "tool_call_id": message["tool_call_id"],
            "content": message["error"] or get_text_content_as_str(message["content"]),
        }
    raise ValueError(f"unsupported message role: {role}")


def _function_to_openai_tool(function: Any) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": function.name,
            "description": function.description,
            "parameters": function.parameters.model_json_schema(),
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
