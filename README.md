# Secure Agentic AI Framework

A security-focused agent framework demonstrating how prompt injection can manipulate an LLM while hard authorization boundaries prevent unauthorized tool execution.

## Core Thesis

The LLM can still be tricked by prompt injection, but authorization is enforced outside the model through a dedicated tool gateway.

## Security Controls

- Dedicated agent identity
- Tool allow-list
- Resource-level authorization
- Short-lived scoped credentials
- Human-in-the-loop approval
- Trust labels for retrieved/tool-returned content
- Audit logging
- Emergency revocation

## Demo

The seeded support document contains an indirect prompt injection attempting to access restricted asset data and create a ticket.

Run the same request in two modes:

- Insecure mode: the agent bypasses the gateway and the restricted asset tool can execute.
- Hardened mode: the model may still request the restricted tool, but the gateway denies it because the tool is not allow-listed.

## Quick Start

```bash
git clone https://github.com/yourusername/secure-agent.git
cd secure-agent
cp .env.example .env
# edit .env and provide OPENAI_API_KEY
docker compose up --build
```

API health check:

```bash
curl http://localhost:8000/api/health
```

Create an agent:

```bash
curl -X POST "http://localhost:8000/api/agent/create?name=northwind-it-agent"
```

The agent identity key is shown once and should be stored securely.

## Validated status

Dependency pins were fixed (`langgraph==1.2.11` / `langchain==1.3.18` / `langchain-core==1.6.1`
/ `langchain-openai==1.6.0` — the original `langgraph==0.2.16` + `langchain==0.3.13` pin
combination was unresolvable). With that fix, `pip install` and all 6 tests pass for real
(not just syntax-checked) against SQLite standing in for Postgres and no Redis running:

```
tests/test_gateway.py::test_tool_allowlist PASSED
tests/test_gateway.py::test_unauthorized_tool_denied PASSED
tests/test_gateway.py::test_credential_scope_is_enforced PASSED
tests/test_injection.py::test_prompt_injection_insecure_succeeds PASSED
tests/test_injection.py::test_prompt_injection_hardened_blocked PASSED
tests/test_injection.py::test_same_injection_different_outcomes PASSED
6 passed in 4.09s
```

The live FastAPI service was also boot-tested over real HTTP against SQLite
(`/api/health`, `/api/agent/create`, `/api/agent/revoke`, `/api/agent/restore`,
`/api/audit/logs`), confirming the persistence and revocation paths work outside pytest too.

**Not yet exercised**: real Postgres, real Redis, or a live LLM endpoint — see
`docs/findings.md` for exactly what was substituted and why, and what to verify yourself
once those services are available. A `streamlit run streamlit_app.py` demo is included and
runs the same insecure-vs-hardened comparison with a deterministic fake LLM (no API key
needed) or a real one if you have `OPENAI_API_KEY` set. `docs/` also has the
before/after architecture, threat model, findings report, and a one-page executive summary
for the portfolio checklist.

**Install streamlit in a separate virtualenv from the API service.** `streamlit==1.62.0`
requires `starlette>=0.46`, but `fastapi==0.115.6` requires `starlette<0.42` — pulling both
into one environment upgrades starlette out from under FastAPI and breaks `FastAPI(...)`
construction at import time (verified: `TypeError: Router.__init__() got an unexpected
keyword argument 'on_startup'`). It's declared as its own `demo` extra in `pyproject.toml`
for exactly this reason:

```bash
python -m venv .venv-demo && source .venv-demo/bin/activate
pip install -e ".[demo]"
streamlit run streamlit_app.py
```

## Verified LLM Stack

The project is pinned to a mutually compatible LangChain stack:

- `langgraph==1.2.11`
- `langchain==1.3.18`
- `langchain-core==1.6.1`
- `langchain-openai==1.6.0`

These versions avoid the incompatible pre-1.0 `langgraph` / `langchain-core` dependency combination used previously.
