import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Approval, ApprovalStatus


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class ApprovalManager:
    @staticmethod
    async def request_approval(
        db: AsyncSession,
        agent_id: uuid.UUID,
        tool_name: str,
        arguments: Dict[str, Any],
        request_id: str,
    ) -> Approval:
        approval = Approval(
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=arguments,
            request_id=request_id,
            status=ApprovalStatus.PENDING,
            expires_at=_utcnow() + timedelta(minutes=15),
        )
        db.add(approval)
        await db.commit()
        await db.refresh(approval)
        return approval

    @staticmethod
    async def resolve_approval(
        db: AsyncSession,
        approval_id: uuid.UUID,
        approved: bool,
        approver: str,
    ) -> Optional[Approval]:
        result = await db.execute(
            select(Approval).where(
                and_(
                    Approval.id == approval_id,
                    Approval.status == ApprovalStatus.PENDING,
                    Approval.expires_at > _utcnow(),
                )
            )
        )
        approval = result.scalar_one_or_none()
        if not approval:
            return None

        approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        approval.approved_by = approver
        approval.resolved_at = _utcnow()
        await db.commit()
        await db.refresh(approval)
        return approval

    @staticmethod
    async def get_approval(db: AsyncSession, approval_id: uuid.UUID) -> Optional[Approval]:
        result = await db.execute(select(Approval).where(Approval.id == approval_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_approved_approval(
        db: AsyncSession,
        agent_id: uuid.UUID,
        tool_name: str,
        request_id: str,
    ) -> Optional[Approval]:
        result = await db.execute(
            select(Approval).where(
                and_(
                    Approval.agent_id == agent_id,
                    Approval.tool_name == tool_name,
                    Approval.request_id == request_id,
                    Approval.status == ApprovalStatus.APPROVED,
                    Approval.expires_at > _utcnow(),
                )
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_pending_approvals(
        db: AsyncSession, agent_id: Optional[uuid.UUID] = None
    ) -> list[Approval]:
        query = select(Approval).where(
            and_(
                Approval.status == ApprovalStatus.PENDING,
                Approval.expires_at > _utcnow(),
            )
        )
        if agent_id:
            query = query.where(Approval.agent_id == agent_id)
        result = await db.execute(query)
        return result.scalars().all()
