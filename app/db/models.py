from datetime import datetime, timedelta, timezone
from enum import Enum
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    TypeDecorator,
    CHAR,
    Enum as SQLEnum,
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

Base = declarative_base()


class GUID(TypeDecorator):
    """Platform-independent UUID type for PostgreSQL and SQLite tests."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, uuid.UUID):
            value = uuid.UUID(str(value))
        return value if dialect.name == "postgresql" else str(value)

    def process_result_value(self, value, dialect):
        if value is None or isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class AgentStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class PermissionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    USER_CONTROLLED = "user_controlled"
    UNTRUSTED = "untrusted"


class Agent(Base):
    __tablename__ = "agents"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    status = Column(SQLEnum(AgentStatus), default=AgentStatus.ACTIVE, nullable=False)
    identity_key = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    permissions = relationship("Permission", back_populates="agent", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="agent", cascade="all, delete-orphan")
    tool_calls = relationship("ToolCall", back_populates="agent", cascade="all, delete-orphan")
    approvals = relationship("Approval", back_populates="agent", cascade="all, delete-orphan")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(GUID(), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    resource_path = Column(String(255))
    permission_type = Column(SQLEnum(PermissionType), default=PermissionType.DENY, nullable=False)
    approval_required = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    agent = relationship("Agent", back_populates="permissions")

    __table_args__ = (Index("idx_permission_agent_tool", "agent_id", "tool_name"),)


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    agent_id = Column(GUID(), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    credential_type = Column(String(50), nullable=False)
    credential_value = Column(String(64), nullable=False, unique=True)
    scopes = Column(JSON, default=list, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True, nullable=False)

    agent = relationship("Agent", back_populates="credentials")


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    agent_id = Column(GUID(), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    arguments = Column(JSON)
    result = Column(JSON)
    trust_label = Column(SQLEnum(TrustLevel), default=TrustLevel.UNTRUSTED, nullable=False)
    was_allowed = Column(Boolean, nullable=False)
    denial_reason = Column(String(255))
    execution_id = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    agent = relationship("Agent", back_populates="tool_calls")

    __table_args__ = (
        Index("idx_toolcall_agent_execution", "agent_id", "execution_id"),
        Index("idx_toolcall_created", "created_at"),
    )


class Approval(Base):
    __tablename__ = "approvals"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    agent_id = Column(GUID(), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    arguments = Column(JSON)
    request_id = Column(String(100), nullable=False)
    status = Column(SQLEnum(ApprovalStatus), default=ApprovalStatus.PENDING, nullable=False)
    approved_by = Column(String(100))
    expires_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc) + timedelta(minutes=15),
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime(timezone=True))

    agent = relationship("Agent", back_populates="approvals")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False)
    agent_id = Column(GUID())
    user_id = Column(String(100))
    details = Column(JSON)
    source_ip = Column(String(45))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_audit_agent_event", "agent_id", "event_type"),
        Index("idx_audit_created", "created_at"),
    )
