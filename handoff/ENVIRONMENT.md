# Environment and gotchas

## Machine

Windows 11, Python 3.13.2. Repo at **`D:\dev\interpose-deva`**.

It was moved off `C:\Users\devan\OneDrive\Desktop\...` because C: was down to ~1 GB free and
OneDrive re-synced every file the test suite touched. **A copy of the old tree may still exist
on C: — it is stale. Ignore it.**

## Setup

```bash
cd D:\dev\interpose-deva
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev,langgraph,bench,ollama]"
```

Extras: `dev` (pytest, ruff, mypy, hypothesis) · `langgraph` (pinned adapter versions) ·
`bench` (agentdojo 0.1.35) · `ollama` (langchain-ollama, demos only).

## Everything you can run

```bash
.venv\Scripts\python.exe -m pytest -q                       # 433 passed, 2 skipped
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m mypy --strict src tests examples

.venv\Scripts\python.exe bench/run_scenarios.py             # self-authored corpus
.venv\Scripts\python.exe bench/run_scenarios.py --strict-integrity
.venv\Scripts\python.exe bench/agentdojo_attacks.py         # third-party corpus
.venv\Scripts\python.exe bench/overhead.py                  # per-call cost

.venv\Scripts\python.exe examples/offline_demo/run.py       # MCP path, deterministic
.venv\Scripts\python.exe examples/langgraph_security_demo.py
```

Real-model demos need Ollama running:

```bash
.venv\Scripts\python.exe examples/ollama_injection_demo.py --model qwen2.5:7b
.venv\Scripts\python.exe examples/react_agent_demo.py --model qwen2.5:7b
.venv\Scripts\python.exe examples/quarantine_demo.py --model qwen2.5:7b
```

## Ollama

Models live on **`D:\ollama-models`** (`OLLAMA_MODELS` is set as a user env var) because C: is
nearly full. `qwen2.5:7b` is pulled; the GPU is an RTX 4050 with 6 GB VRAM, so ~7B at Q4 is the
practical ceiling.

```bash
ollama list        # models on disk
ollama ps          # what is loaded in VRAM right now (empty when idle — unloads after 5 min)
ollama serve       # start the server
```

If a demo cannot reach it, the server is probably not running. Start it with
`OLLAMA_MODELS=D:\ollama-models` in the environment, or it will look at the empty C: location.

Ollama also exposes an **OpenAI-compatible endpoint** at `http://127.0.0.1:11434/v1`, which is
how AgentDojo runs against a local model:

```bash
OPENAI_BASE_URL=http://127.0.0.1:11434/v1 OPENAI_API_KEY=ollama-local \
  .venv\Scripts\python.exe bench/agentdojo_runner.py --mode undefended \
  --pipeline agentdojo --attack direct --suite workspace --model qwen2.5:7b ...
```

## Gotchas that have already cost time

**`env={}` in subprocess.** Demos launch children with an explicit environment to prove they
need no credentials. On Windows that also withholds `SYSTEMROOT`, which `import asyncio` needs.
Use `credential_free_environment()` (`tests/conftest.py`) or the local copy in
`examples/offline_demo/run.py`.

**Colons in model names.** `qwen2.5:7b` is an invalid Windows path component, and AgentDojo
uses the pipeline name as a directory. `_filesystem_safe_name()` in `bench/agentdojo_runner.py`
handles it.

**Long pytest parameter IDs.** pytest writes the full test ID into `PYTEST_CURRENT_TEST`, and
Windows caps environment variables at 32767 characters. A parametrized case containing a
32769-character string crashed at setup. Give long params explicit short `pytest.param(id=...)`.

**POSIX-only tests.** `chmod` permission bits and symlink creation are skipped on Windows with
stated reasons. That is why the suite shows 2 skips.

**Disk.** C: hovers near full. Keep model pulls and scratch output on D:.

## Git

Remote `origin` → `github.com/Devx228/interpose-deva`, branch `main`.

**Commits must credit Devansh alone** — no co-author trailers. `includeCoAuthoredBy: false` is
set in `~/.claude/settings.json`; verify with `git log -1 --format='%B'` after the first commit
on a new machine.
