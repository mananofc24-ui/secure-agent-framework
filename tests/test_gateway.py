import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.db.models import Base
from app.security.credentials import CredentialManager
from app.security.gateway import ToolGateway
from app.security.identity import IdentityManager
from app.security.policy import AgentPolicy, PermissionRule, PolicyEngine


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def policy_engine():
    policy = AgentPolicy(
        agent_name="northwind-it-agent",
        tools={
            "read_document": PermissionRule(
                tool_name="read_document",
                allowed=True,
                resources=["support_docs"],
                resource_path_allowlist=["document:support_"],
            ),
            "create_ticket": PermissionRule(
                tool_name="create_ticket",
                allowed=True,
                approval_required=True,
                resource_path_allowlist=["service_tickets"],
            ),
            "query_asset_inventory": PermissionRule(
                tool_name="query_asset_inventory",
                allowed=False,
            ),
        },
    )
    engine = PolicyEngine()
    engine.load_policy_dict(policy.model_dump())
    return engine


@pytest.mark.asyncio
async def test_tool_allowlist(db, policy_engine):
    agent = await IdentityManager.create_agent(db, "northwind-it-agent", "Test")

    async def fake_read_document(document_id: str):
        return {"document_id": document_id}

    gateway = ToolGateway(db, policy_engine, {"read_document": fake_read_document})
    result = await gateway.execute_tool(
        agent_identity_key=agent._raw_key,
        tool_name="read_document",
        arguments={"document_id": "support_001"},
        execution_id="test-001",
    )
    assert result["success"] is True
    assert result["result"]["document_id"] == "support_001"
    assert result["credential_used"] is True


@pytest.mark.asyncio
async def test_unauthorized_tool_denied(db, policy_engine):
    agent = await IdentityManager.create_agent(db, "northwind-it-agent", "Test")
    gateway = ToolGateway(db, policy_engine, {})
    result = await gateway.execute_tool(
        agent_identity_key=agent._raw_key,
        tool_name="query_asset_inventory",
        arguments={"asset_id": "ASSET-1042"},
        execution_id="test-002",
    )
    assert result["success"] is False
    assert result["reason"] == "TOOL_NOT_ALLOWLISTED"


@pytest.mark.asyncio
async def test_credential_scope_is_enforced(db, policy_engine):
    agent = await IdentityManager.create_agent(db, "northwind-it-agent", "Test")
    raw_cred, _ = await CredentialManager.issue_credential(
        db, agent.id, ["tool:create_ticket"], ttl_minutes=5
    )

    async def fake_read_document(document_id: str):
        return {"document_id": document_id}

    gateway = ToolGateway(db, policy_engine, {"read_document": fake_read_document})
    result = await gateway.execute_tool(
        agent_identity_key=agent._raw_key,
        tool_name="read_document",
        arguments={"document_id": "support_001"},
        execution_id="test-003",
        credential_key=raw_cred,
    )
    assert result["success"] is False
    assert result["error"] == "INVALID_CREDENTIAL"
