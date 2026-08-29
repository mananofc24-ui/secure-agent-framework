# Executive Summary — Securing the Northwind IT Agent

**Bottom line**: An AI agent with tool access is only as safe as the boundary between "the
model decided to do something" and "the something happened." We proved this with a working
attack and a working fix, both against the same agent, and verified both by actually running
the code rather than just reading it.

## What we tested

An internal IT-support agent that can read documents, create tickets, and look up device
records. We planted a hidden instruction inside a support document the agent reads as part
of normal, expected use — not a jailbreak in the user's own message.

## What happened without protection

The hidden instruction fooled the agent into requesting a restricted device record, with
nothing in the system stopping the tool from actually running.

## What happened with protection

We ran the exact same attack against a hardened version of the agent, using the identical
model and prompt. The model was fooled the same way — it still requested the restricted
tool. The dangerous action did not happen. A gateway sitting between the model and its
tools — independent of the model, unable to be argued with — checks agent identity,
revocation status, a least-privilege policy, and (for high-impact actions) human approval,
before anything executes. Every request, allowed or denied, is written to an audit trail.

## Why this matters

You cannot currently guarantee a language model will resist a cleverly worded instruction
buried in data it reads. You can guarantee what happens after it decides to act, if you put
a real authorization boundary in the way — one the model cannot see, edit, or satisfy on its
own. That's the difference between an interesting failure and an incident.

## What we built and verified

- Least-privilege allow-list plus resource-level permissions, enforced outside the model
- Human approval required for high-impact actions, bound to the exact arguments requested
- Short-lived, scoped credentials, issued per call
- Persisted audit trail of every tool-call decision, not just successful ones
- Instant revocation, checked before policy on every subsequent call
- 6/6 tests passing against the pinned dependency set, plus a live HTTP smoke test of the
  running service

## Known gaps

Not yet exercised against real Postgres, real Redis, or a live LLM endpoint — validated
against SQLite, the built-in Redis fallback, and a deterministic fake model standing in for
those. See `docs/findings.md` for the specifics.

## Recommendation

Treat this pattern — model proposes, gateway disposes — as the minimum bar for any agent
given access to sensitive data or write actions, not an optional hardening pass added later.
