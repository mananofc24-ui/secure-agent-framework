# Threat Model

## Scenario

Northwind Retail's internal IT-support agent has three tools: read support documents, create
a service ticket, and query a fictional asset inventory. A support document the agent
retrieves as part of normal operation has been altered to contain text formatted as a system
instruction (see `attack/malicious_document.md`).

## Attack technique

**Indirect prompt injection** (OWASP LLM01, retrieved-content variant): the attacker never
talks to the agent directly. The payload rides inside data the agent fetches on the user's
behalf. A model with no defense treats retrieved content and system instructions as equally
authoritative.

## Impact if unmitigated

- Disclosure of restricted asset data.
- Creation of a ticket embedding leaked data, propagating the disclosure further.
- Neither action requested or approved by an accountable human.

## Mitigations implemented and why each matters

| Control | Implementation | Stops / limits |
|---|---|---|
| Dedicated agent identity | `app/security/identity.py` (`IdentityManager`) | Every action attributable to a governable agent identity, verified on every call |
| Tool allow-list + resource scope | `app/security/policy.py` (`PolicyEngine`), `policies/hardened.yaml` | The actual boundary — denies the restricted tool independent of what the model requests |
| Human-in-the-loop | `app/security/approval.py` (`ApprovalManager`) | High-impact actions require an approval bound to the exact arguments requested; the model cannot self-approve |
| Short-lived scoped credentials | `app/security/credentials.py` (`CredentialManager`), 5-min TTL | Even an authorized call only gets a narrowly scoped, time-limited credential, not standing access |
| Trust labels | `app/db/models.py` (`TrustLevel`), passed into `execute_tool` | Defense-in-depth signal that retrieved content is data, not instruction — does not by itself stop anything |
| Audit logging | `app/audit/logger.py` (`AuditLogger`) | Every request/decision, allowed or denied, is persisted with agent id, tool, and reason |
| Emergency revocation | `app/security/revocation.py` (`RevocationManager`, Redis + DB fallback) | Agent access can be killed instantly and takes effect on the very next call, before policy is even checked |

## What this project does NOT claim

It does not claim to make the LLM immune to prompt injection. `test_prompt_injection_hardened_blocked`
specifically allows the fake/real model to still request the restricted tool — the assertion
is on what the gateway does with that request, not on whether the model asked for it.

## Reference mapping

| Risk | Reference |
|---|---|
| Goal hijacking, tool misuse, memory poisoning, identity/privilege abuse | [OWASP GenAI Security — Agentic AI Threats](https://genai.owasp.org/) |
| Prompt injection origin | [OWASP LLM01](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| System prompt / rule leakage | [OWASP LLM07](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| Adversary tactics | [MITRE ATLAS](https://atlas.mitre.org/) |
| Least privilege, approvals, auditability principles | [CISA AI guidance](https://www.cisa.gov/ai) |
