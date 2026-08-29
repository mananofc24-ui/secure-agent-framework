import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import AuditLogger
from app.db.models import ToolCall, TrustLevel
from app.security.approval import ApprovalManager
from app.security.credentials import CredentialManager
from app.security.identity import IdentityManager
from app.security.policy import PolicyEngine
from app.security.revocation import RevocationManager

ToolFunc = Callable[..., Awaitable[Any]]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class ToolGateway:
    def __init__(self, db: AsyncSession, policy_engine: PolicyEngine, tool_registry: Dict[str, ToolFunc]):
        self.db = db
        self.policy_engine = policy_engine
        self.tool_registry = tool_registry
        self.audit_logger = AuditLogger(db)

    @staticmethod
    def _resource_from_arguments(arguments: Dict[str, Any]) -> Optional[str]:
        resource_type = arguments.get("resource_type")
        resource_id = arguments.get("resource_id")
        if resource_type and resource_id:
            return f"{resource_type}:{resource_id}"
        if "document_id" in arguments:
            return f"document:{arguments['document_id']}"
        if "asset_id" in arguments:
            return f"asset:{arguments['asset_id']}"
        if arguments.get("resource"):
            return str(arguments["resource"])
        return None
        return None

    async def execute_tool(
        self,
        agent_identity_key: str,
        tool_name: str,
        arguments: Dict[str, Any],
        execution_id: str,
        trust_label: str = TrustLevel.USER_CONTROLLED.value,
        credential_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        # 1. Verify agent identity.
        agent_identity = await IdentityManager.verify_agent(self.db, agent_identity_key)
        if not agent_identity:
            return {"success": False, "error": "INVALID_AGENT_IDENTITY"}

        # 2. Emergency revocation.
        if await RevocationManager.is_revoked(self.db, agent_identity.id):
            return {"success": False, "error": "AGENT_REVOKED"}

        # 3. Policy and resource authorization happen before credentials so an
        #    unallowlisted tool is denied without needing a standing credential.
        resource = self._resource_from_arguments(arguments)
        if resource is None and tool_name == "create_ticket":
            resource = "service_tickets"

        auth_result = self.policy_engine.authorize(
            agent_name=agent_identity.name,
            tool_name=tool_name,
            resource=resource,
            arguments=arguments,
        )

        if not auth_result.get("allowed", False):
            return await self._record_denial(
                agent_identity.id,
                tool_name,
                arguments,
                execution_id,
                trust_label,
                auth_result.get("reason", "DENIED"),
            )

        # 4. HITL for high-impact actions.
        if auth_result.get("approval_required", False):
            approved = await ApprovalManager.get_approved_approval(
                self.db,
                agent_id=agent_identity.id,
                tool_name=tool_name,
                request_id=execution_id,
            )
            if not approved:
                approval = await ApprovalManager.request_approval(
                    self.db,
                    agent_id=agent_identity.id,
                    tool_name=tool_name,
                    arguments=arguments,
                    request_id=execution_id,
                )
                return {
                    "success": False,
                    "error": "APPROVAL_REQUIRED",
                    "approval_id": str(approval.id),
                }

            if _aware(approved.expires_at) <= _utcnow():
                return {"success": False, "error": "APPROVAL_EXPIRED"}

            # Bind the approval to the exact requested arguments.
            if (approved.arguments or {}) != arguments:
                return {"success": False, "error": "APPROVAL_ARGUMENT_MISMATCH"}

        # 5. Verify caller-supplied credential or issue an ephemeral one.
        if credential_key:
            scoped_credential = await CredentialManager.verify_credential(
                self.db,
                credential_key,
                required_scope=f"tool:{tool_name}",
                agent_id=agent_identity.id,
            )
            if not scoped_credential:
                return {"success": False, "error": "INVALID_CREDENTIAL"}
        else:
            credential_key, _ = await CredentialManager.issue_credential(
                self.db,
                agent_id=agent_identity.id,
                scopes=[f"tool:{tool_name}"],
                ttl_minutes=5,
            )

        # 6. Persist the tool-call decision.
        tool_call = ToolCall(
            agent_id=agent_identity.id,
            tool_name=tool_name,
            arguments=arguments,
            trust_label=TrustLevel(trust_label),
            was_allowed=True,
            execution_id=execution_id,
        )
        self.db.add(tool_call)
        await self.db.flush()

        # 7. Execute only through the gateway registry.
        tool_func = self.tool_registry.get(tool_name)
        if not tool_func:
            tool_call.was_allowed = False
            tool_call.denial_reason = "TOOL_NOT_IMPLEMENTED"
            await self.db.commit()
            return {"success": False, "error": "TOOL_NOT_IMPLEMENTED"}

        try:
            result = await tool_func(**arguments)
            tool_call.result = result
            await self.db.commit()
            await self.audit_logger.log_event(
                event_type="TOOL_EXECUTED",
                agent_id=agent_identity.id,
                details={
                    "tool_name": tool_name,
                    "execution_id": execution_id,
                    "tool_call_id": str(tool_call.id),
                    "credential_used": True,
                },
            )
            return {
                "success": True,
                "result": result,
                "tool_call_id": str(tool_call.id),
                "credential_used": True,
            }
        except Exception as exc:
            await self.db.rollback()
            return {"success": False, "error": "TOOL_EXECUTION_FAILED", "message": str(exc)}

    async def _record_denial(
        self,
        agent_id: uuid.UUID,
        tool_name: str,
        arguments: Dict[str, Any],
        execution_id: str,
        trust_label: str,
        reason: str,
    ) -> Dict[str, Any]:
        tool_call = ToolCall(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            trust_label=TrustLevel(trust_label),
            was_allowed=False,
            denial_reason=reason,
            execution_id=execution_id,
        )
        self.db.add(tool_call)
        await self.db.flush()
        await self.db.commit()
        await self.audit_logger.log_event(
            event_type="TOOL_BLOCKED",
            agent_id=agent_id,
            details={
                "tool_name": tool_name,
                "execution_id": execution_id,
                "reason": reason,
                "tool_call_id": str(tool_call.id),
            },
        )
        return {
            "success": False,
            "error": "DENIED",
            "reason": reason,
            "tool_call_id": str(tool_call.id),
        }
