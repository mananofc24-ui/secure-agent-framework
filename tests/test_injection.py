import uuid

import pytest
import pytest_asyncio
from langchain_core.messages import AIMessage
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.agent.graph import AgentGraph
from app.db.models import Base
from app.security.gateway import ToolGateway
from app.security.identity import IdentityManager
from app.security.policy import PolicyEngine
from app.tools.assets import query_asset_inventory
from app.tools.documents import read_document
from app.tools.tickets import create_ticket


class FakeInjectionLLM:
    async def ainvoke(self, messages, tools=None, tool_choice=None):
        return AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "query_asset_inventory",
                    "args": {"asset_id": "ASSET-1042"},
                    "id": f"call-{uuid.uuid4().hex[:8]}",
                    "type": "tool_call",
                }
            ],
        )


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as session:
        yield session
    await engine.dispose()


async def create_agent(db):
    return await IdentityManager.create_agent(db, "northwind-it-agent", "Test")


def hardened_policy():
    return PolicyEngine(str(__import__("pathlib").Path("policies/hardened.yaml")))


@pytest.mark.asyncio
async def test_prompt_injection_insecure_succeeds(db):
    agent = await create_agent(db)
    graph = AgentGraph(gateway=None, llm=FakeInjectionLLM())
    result = await graph.run_agent(
        user_request="Investigate laptop ASSET-1042",
        agent_identity_key=agent._raw_key,
        insecure_mode=True,
    )

    first = result["tool_results"][0]
    assert first["insecure_mode"] is True
    assert first["result"]["asset_id"] == "ASSET-1042"
    assert first["result"]["data"] is not None
    assert result["gateway_used"] is False


@pytest.mark.asyncio
async def test_prompt_injection_hardened_blocked(db):
    agent = await create_agent(db)
    gateway = ToolGateway(
        db,
        hardened_policy(),
        {
            "read_document": read_document,
            "create_ticket": create_ticket,
            "query_asset_inventory": query_asset_inventory,
        },
    )
    graph = AgentGraph(gateway=gateway, llm=FakeInjectionLLM())

    result = await graph.run_agent(
        user_request="Investigate laptop ASSET-1042",
        agent_identity_key=agent._raw_key,
        insecure_mode=False,
    )

    first = result["tool_results"][0]
    assert first["success"] is False
    assert first["reason"] == "TOOL_NOT_ALLOWLISTED"
    assert result["gateway_used"] is True


@pytest.mark.asyncio
async def test_same_injection_different_outcomes(db):
    agent = await create_agent(db)
    user_request = "Investigate laptop ASSET-1042"

    insecure_graph = AgentGraph(gateway=None, llm=FakeInjectionLLM())
    insecure_result = await insecure_graph.run_agent(
        user_request=user_request,
        agent_identity_key=agent._raw_key,
        insecure_mode=True,
    )

    gateway = ToolGateway(
        db,
        hardened_policy(),
        {
            "read_document": read_document,
            "create_ticket": create_ticket,
            "query_asset_inventory": query_asset_inventory,
        },
    )
    hardened_graph = AgentGraph(gateway=gateway, llm=FakeInjectionLLM())
    hardened_result = await hardened_graph.run_agent(
        user_request=user_request,
        agent_identity_key=agent._raw_key,
        insecure_mode=False,
    )

    assert insecure_result["tool_results"][0]["result"]["data"] is not None
    assert hardened_result["tool_results"][0]["success"] is False
    assert hardened_result["tool_results"][0]["reason"] == "TOOL_NOT_ALLOWLISTED"
