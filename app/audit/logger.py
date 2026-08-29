import uuid
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog


class AuditLogger:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_event(
        self,
        event_type: str,
        agent_id: Optional[uuid.UUID] = None,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
    ) -> AuditLog:
        log = AuditLog(
            event_type=event_type,
            agent_id=agent_id,
            user_id=user_id,
            details=details or {},
            source_ip=source_ip,
        )
        self.db.add(log)
        await self.db.commit()
        await self.db.refresh(log)
        return log

    async def log_agent_request(self, agent_id: uuid.UUID, user_request: str, execution_id: str) -> AuditLog:
        return await self.log_event(
            event_type="AGENT_REQUEST",
            agent_id=agent_id,
            details={"request": user_request, "execution_id": execution_id},
        )

    async def log_tool_call(
        self,
        agent_id: uuid.UUID,
        tool_name: str,
        arguments: Dict[str, Any],
        allowed: bool,
        reason: Optional[str] = None,
    ) -> AuditLog:
        return await self.log_event(
            event_type="TOOL_CALL",
            agent_id=agent_id,
            details={
                "tool_name": tool_name,
                "arguments": arguments,
                "allowed": allowed,
                "reason": reason,
            },
        )
