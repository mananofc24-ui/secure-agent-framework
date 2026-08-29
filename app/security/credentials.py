import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Credential


class ScopedCredential:
    def __init__(self, credential_id: uuid.UUID, scopes: List[str], expires_at: datetime, agent_id: uuid.UUID):
        self.credential_id = credential_id
        self.scopes = scopes
        self.expires_at = expires_at
        self.agent_id = agent_id

    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now >= expires

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "*" in self.scopes


class CredentialManager:
    @staticmethod
    async def issue_credential(
        db: AsyncSession,
        agent_id: uuid.UUID,
        scopes: List[str],
        ttl_minutes: int = 5,
        credential_type: str = "ephemeral",
    ) -> tuple[str, Credential]:
        raw_key = secrets.token_urlsafe(24)
        hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)

        credential = Credential(
            agent_id=agent_id,
            credential_type=credential_type,
            credential_value=hashed_key,
            scopes=scopes,
            expires_at=expires_at,
            is_active=True,
        )
        db.add(credential)
        await db.commit()
        await db.refresh(credential)
        return raw_key, credential

    @staticmethod
    async def verify_credential(
        db: AsyncSession,
        credential_key: str,
        required_scope: Optional[str] = None,
        agent_id: Optional[uuid.UUID] = None,
    ) -> Optional[ScopedCredential]:
        hashed_key = hashlib.sha256(credential_key.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        query = select(Credential).where(
            and_(
                Credential.credential_value == hashed_key,
                Credential.is_active.is_(True),
                Credential.expires_at > now,
            )
        )
        if agent_id is not None:
            query = query.where(Credential.agent_id == agent_id)

        result = await db.execute(query)
        credential = result.scalar_one_or_none()
        if not credential:
            return None

        scoped = ScopedCredential(
            credential_id=credential.id,
            scopes=credential.scopes or [],
            expires_at=credential.expires_at,
            agent_id=credential.agent_id,
        )
        if required_scope and not scoped.has_scope(required_scope):
            return None
        return scoped

    @staticmethod
    async def revoke_credentials(db: AsyncSession, agent_id: uuid.UUID) -> int:
        result = await db.execute(select(Credential).where(Credential.agent_id == agent_id))
        credentials = result.scalars().all()
        for credential in credentials:
            credential.is_active = False
        await db.commit()
        return len(credentials)
