# Findings Report — Northwind IT Agent Security Assessment

## Summary

The insecure version of the Northwind IT-support agent has no authorization boundary
between a model deciding to call a tool and the tool executing. An indirect prompt injection
seeded in a routinely-retrieved support document is sufficient to make the agent disclose
restricted asset data. The hardened version, using the identical model, prompt, and
document, is not vulnerable to this attack — not because the model resists the injection,
but because `ToolGateway.execute_tool()` sits between the model's request and execution.

## Vulnerability

- **Type**: Indirect prompt injection (OWASP LLM01), retrieved-content variant
- **Entry point**: seeded support document (`attack/malicious_document.md`)
- **Affected tool**: `query_asset_inventory` (confidentiality); `create_ticket` if requested
  with elevated priority (unauthorized action)
- **Preconditions**: attacker needs write access to a document the agent retrieves during
  normal operation — no direct access to the agent or its prompt required

## Exploit and retest evidence

Both directions were verified by actually running the test suite in this environment
(not merely inspecting the code):

```
tests/test_gateway.py::test_tool_allowlist PASSED
tests/test_gateway.py::test_unauthorized_tool_denied PASSED
tests/test_gateway.py::test_credential_scope_is_enforced PASSED
tests/test_injection.py::test_prompt_injection_insecure_succeeds PASSED
tests/test_injection.py::test_prompt_injection_hardened_blocked PASSED
tests/test_injection.py::test_same_injection_different_outcomes PASSED

6 passed in 4.09s
```

run against the pinned dependency set in `pyproject.toml`
(`langgraph==1.2.11`, `langchain==1.3.18`, `langchain-core==1.6.1`, `langchain-openai==1.6.0`,
`fastapi==0.115.6`, `sqlalchemy==2.0.37`, ...), with SQLite via `aiosqlite` standing in for
Postgres and no Redis instance running (`RevocationManager` falls back to the DB check
without erroring).

`test_prompt_injection_insecure_succeeds` confirms the direct-call path executes the
restricted tool when a fake LLM requests it. `test_prompt_injection_hardened_blocked`
confirms the same request, routed through `ToolGateway`, is denied with the tool never
reaching execution. `test_same_injection_different_outcomes` runs both paths against the
identical injected input and asserts the outcomes diverge only at the gateway.

The live FastAPI service was also exercised directly over HTTP (`/api/health`,
`/api/agent/create`, `/api/agent/revoke`, `/api/agent/restore`, `/api/audit/logs`) against
the same SQLite substitution, confirming the persistence and revocation paths work outside
of pytest, not just inside it.

## Root cause

The insecure design treats "the model produced a tool_call" and "the tool call is
authorized" as the same event. They are not: the model's decision is influenceable by
anything in its context window, including attacker-controlled retrieved content.
Authorization has to be decided by something the retrieved content cannot influence.

## Recommendation

Adopt the hardened architecture as the baseline pattern for any agent with tool access to
sensitive resources — see `docs/architecture-after.md` for the enforcement order and
`docs/threat-model.md` for the full control-to-reference mapping.

## Known gaps / not yet exercised against real infrastructure

- Not run against real Postgres or real Redis — SQLite and the in-code Redis fallback were
  used as substitutes in this environment, since neither service nor outbound network access
  to install/run them was available here.
- Not run against a real OpenAI (or other live LLM) endpoint — `test_prompt_injection_*`
  uses a deterministic fake LLM standing in for the model, so the *gateway's* behavior is
  proven, but a live model's specific phrasing/tool-call choices for this exact injection
  have not been observed end-to-end in this environment.
- Minor response-contract detail: `POST /api/agent/revoke/{id}` returns `422` if the
  `X-Admin-API-Key` header is omitted entirely, vs `401` if it's present but wrong — both
  block the action, but the status codes differ depending on how the caller fails auth.
- `streamlit==1.62.0` (added for the demo UI) conflicts with `fastapi==0.115.6` if installed
  into the same environment — streamlit requires `starlette>=0.46`, fastapi requires
  `starlette<0.42`, and installing both upgrades starlette out from under FastAPI, breaking
  `FastAPI(...)` construction at import time (verified directly, not theoretical). Fixed by
  moving streamlit to its own `demo` extra in `pyproject.toml`, meant to be installed in a
  separate virtualenv from the API service — see README for the exact commands.
