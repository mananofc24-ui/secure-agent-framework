import os
import uuid

import redis.asyncio as redis
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Agent, AgentStatus


REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379/0",
)


class RevocationManager:
    """
    Handles agent revocation using both Redis and PostgreSQL.

    Redis provides a fast revocation lookup.

    PostgreSQL remains the authoritative fallback so revocation
    still works if Redis is unavailable.
    """

    _redis = None

    # ========================================================================
    # REDIS CONNECTION
    # ========================================================================

    @classmethod
    async def get_redis(cls):
        """
        Lazily create and return the shared Redis client.
        """

        if cls._redis is None:
            cls._redis = redis.from_url(
                REDIS_URL,
                decode_responses=True,
            )

        return cls._redis

    @classmethod
    async def close_redis(cls) -> None:
        """
        Explicitly close the shared Redis client.

        This is important because redis.asyncio owns resources that
        must be closed before the asyncio event loop shuts down.
        """

        if cls._redis is None:
            return

        try:
            await cls._redis.aclose()
        finally:
            cls._redis = None

    # ========================================================================
    # REVOKE
    # ========================================================================

    @classmethod
    async def revoke_agent(
        cls,
        db: AsyncSession,
        agent_id: uuid.UUID,
        reason: str = "Manual revocation",
    ) -> bool:
        """
        Revoke an agent in PostgreSQL and cache the revocation in Redis.
        """

        result = await db.execute(
            select(Agent).where(
                Agent.id == agent_id
            )
        )

        agent = result.scalar_one_or_none()

        if not agent:
            return False

        # PostgreSQL is the persistent source of truth.
        agent.status = AgentStatus.REVOKED

        await db.commit()

        # Redis is a fast cache.
        try:
            client = await cls.get_redis()

            await client.setex(
                f"revocation:{agent_id}",
                86400,
                reason,
            )

        except Exception:
            # Revocation remains valid because PostgreSQL was updated.
            pass

        return True

    # ========================================================================
    # CHECK REVOCATION
    # ========================================================================

    @classmethod
    async def is_revoked(
        cls,
        db: AsyncSession,
        agent_id: uuid.UUID,
    ) -> bool:
        """
        Check whether an agent is revoked.

        Lookup order:

            Redis
              ↓
            PostgreSQL fallback
        """

        # --------------------------------------------------------------------
        # Fast Redis lookup
        # --------------------------------------------------------------------

        try:
            client = await cls.get_redis()

            cached_reason = await client.get(
                f"revocation:{agent_id}"
            )

            if cached_reason is not None:
                return True

        except Exception:
            # Fall back to PostgreSQL.
            pass

        # --------------------------------------------------------------------
        # PostgreSQL fallback
        # --------------------------------------------------------------------

        result = await db.execute(
            select(Agent).where(
                and_(
                    Agent.id == agent_id,
                    Agent.status == AgentStatus.REVOKED,
                )
            )
        )

        agent = result.scalar_one_or_none()

        if agent:
            # Re-populate Redis cache when possible.
            try:
                client = await cls.get_redis()

                await client.setex(
                    f"revocation:{agent_id}",
                    86400,
                    "Database revocation",
                )

            except Exception:
                pass

            return True

        return False

    # ========================================================================
    # RESTORE
    # ========================================================================

    @classmethod
    async def restore_agent(
        cls,
        db: AsyncSession,
        agent_id: uuid.UUID,
    ) -> bool:
        """
        Restore a revoked agent to ACTIVE state and remove its
        Redis revocation marker.
        """

        result = await db.execute(
            select(Agent).where(
                Agent.id == agent_id
            )
        )

        agent = result.scalar_one_or_none()

        if not agent:
            return False

        # PostgreSQL is updated first.
        agent.status = AgentStatus.ACTIVE

        await db.commit()

        # Remove the Redis cache entry.
        try:
            client = await cls.get_redis()

            await client.delete(
                f"revocation:{agent_id}"
            )

        except Exception:
            # Database state remains authoritative.
            pass

        return True