import hashlib
import secrets
import uuid
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Agent, AgentStatus


class AgentIdentity(BaseModel):
    id: uuid.UUID
    name: str
    identity_key: str
    status: AgentStatus

    model_config = {"use_enum_values": True}


class IdentityManager:
    @staticmethod
    async def create_agent(db: AsyncSession, name: str, description: str = "") -> Agent:
        raw_key = secrets.token_urlsafe(32)
        identity_key = hashlib.sha256(raw_key.encode()).hexdigest()

        agent = Agent(
            name=name,
            description=description,
            identity_key=identity_key,
            status=AgentStatus.ACTIVE,
        )
        db.add(agent)
        await db.commit()
        await db.refresh(agent)
        agent._raw_key = raw_key
        return agent

    @staticmethod
    async def get_agent_by_id(db: AsyncSession, agent_id: uuid.UUID) -> Optional[Agent]:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_agent_by_key(db: AsyncSession, identity_key: str) -> Optional[Agent]:
        hashed = hashlib.sha256(identity_key.encode()).hexdigest()
        result = await db.execute(select(Agent).where(Agent.identity_key == hashed))
        return result.scalar_one_or_none()

    @staticmethod
    async def verify_agent(db: AsyncSession, identity_key: str) -> Optional[AgentIdentity]:
        agent = await IdentityManager.get_agent_by_key(db, identity_key)
        if not agent or agent.status != AgentStatus.ACTIVE:
            return None
        return AgentIdentity(
            id=agent.id,
            name=agent.name,
            identity_key=agent.identity_key,
            status=agent.status,
        )
