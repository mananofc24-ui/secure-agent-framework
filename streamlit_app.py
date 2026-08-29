"""
Streamlit demo UI, side by side insecure vs hardened.

Run with:

    streamlit run streamlit_app.py

By default this uses a deterministic fake LLM (the same one `tests/test_injection.py` uses)
that always requests the restricted asset lookup, so the demo works with no API key and no
external services — an in-memory SQLite DB is created fresh on each run. Uncheck "Use fake
injection LLM" to route through a real OpenAI-compatible model instead, if OPENAI_API_KEY
(or LLM_BASE_URL/LLM_API_KEY for another OpenAI-compatible provider) is set in your
environment.
"""
import asyncio
import uuid

import streamlit as st
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

st.set_page_config(page_title="Northwind Secure Agent Demo", layout="wide")
st.title("Northwind IT Agent — Insecure vs Hardened")

DEFAULT_MESSAGE = "Investigate laptop ASSET-1042"


class FakeInjectionLLM:
    """Always requests the restricted tool, simulating a model fully fooled by the
    seeded injection — no API key required. This is the same fake used in
    tests/test_injection.py, so the demo mirrors what the automated test proves."""

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


async def run_both(user_request: str, use_fake_llm: bool):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session = async_sessionmaker(engine, expire_on_commit=False)

    async with async_session() as db:
        agent = await IdentityManager.create_agent(db, "northwind-it-agent", "Streamlit demo")
        agent_key = agent._raw_key

        llm = FakeInjectionLLM() if use_fake_llm else None  # None -> AgentGraph defaults to ChatOpenAI

        insecure_graph = AgentGraph(gateway=None, llm=llm)
        insecure_result = await insecure_graph.run_agent(
            user_request=user_request, agent_identity_key=agent_key, insecure_mode=True,
        )

        policy = PolicyEngine("policies/hardened.yaml")
        gateway = ToolGateway(
            db, policy,
            {
                "read_document": read_document,
                "create_ticket": create_ticket,
                "query_asset_inventory": query_asset_inventory,
            },
        )
        hardened_llm = FakeInjectionLLM() if use_fake_llm else None
        hardened_graph = AgentGraph(gateway=gateway, llm=hardened_llm)
        hardened_result = await hardened_graph.run_agent(
            user_request=user_request, agent_identity_key=agent_key, insecure_mode=False,
        )

    await engine.dispose()
    return insecure_result, hardened_result


message = st.text_area("User request", value=DEFAULT_MESSAGE, height=80)
use_fake_llm = st.checkbox(
    "Use fake injection LLM (no API key needed)", value=True,
    help="Uncheck to use a real OpenAI-compatible model via OPENAI_API_KEY / LLM_BASE_URL.",
)

if st.button("Run attack against both agents"):
    with st.spinner("Running both agents against the same seeded document..."):
        insecure_result, hardened_result = asyncio.run(run_both(message, use_fake_llm))

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🔓 Insecure (no gateway)")
        st.json(insecure_result["tool_results"])
        first = insecure_result["tool_results"][0] if insecure_result["tool_results"] else {}
        if first.get("result", {}).get("data") is not None:
            st.error("❌ UNAUTHORIZED ACCESS — restricted asset data returned")
        else:
            st.info("No restricted data returned this run")

    with col2:
        st.subheader("🔒 Hardened (ToolGateway)")
        st.json(hardened_result["tool_results"])
        first = hardened_result["tool_results"][0] if hardened_result["tool_results"] else {}
        if first.get("success") is False:
            st.success(f"✅ Blocked — reason: {first.get('reason')}")
        else:
            st.warning("Call succeeded — check policies/hardened.yaml")
