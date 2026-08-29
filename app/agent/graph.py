import os
import uuid
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph

try:
    from langgraph.checkpoint.memory import InMemorySaver
except ImportError:
    InMemorySaver = None

from app.agent.prompts import get_agent_prompt
from app.agent.state import AgentState
from app.security.trust import TrustLevel, TrustManager
from app.tools.assets import query_asset_inventory
from app.tools.documents import SUPPORT_DOCUMENTS, read_document
from app.tools.tickets import create_ticket


# ============================================================================
# ENVIRONMENT
# ============================================================================

load_dotenv()


# ============================================================================
# LANGCHAIN TOOLS
# ============================================================================

@tool("read_document")
async def llm_read_document(
    document_id: str,
) -> Dict[str, Any]:
    """Read a Northwind IT support document."""
    return await read_document(document_id)


@tool("create_ticket")
async def llm_create_ticket(
    title: str,
    description: str,
    priority: str = "medium",
) -> Dict[str, Any]:
    """Create a Northwind IT service ticket."""
    return await create_ticket(
        title=title,
        description=description,
        priority=priority,
    )


@tool("query_asset_inventory")
async def llm_query_asset_inventory(
    asset_id: str,
) -> Dict[str, Any]:
    """Query restricted Northwind asset inventory."""
    return await query_asset_inventory(
        asset_id
    )


# ============================================================================
# AGENT GRAPH
# ============================================================================

class AgentGraph:
    """
    Northwind IT support agent.

    Normal flow:

        retrieve_documents
                ↓
            llm_reason
                ↓
           execute_tool
                ↓
          final_response

    Security model:

        INSECURE
        --------
        Tool decision → direct execution

        HARDENED
        --------
        Tool decision → ToolGateway → policy/security → execution

    The support_001 document is a controlled prompt-injection fixture.
    For this known fixture, the tool decision is deterministic so that
    the security experiment does not depend on stochastic LLM behavior.
    """

    def __init__(self, gateway=None, llm=None):
        self.gateway = gateway

        if llm is not None:
            # Dependency injection for tests.
            # FakeInjectionLLM can be supplied by the test suite.
            self.llm = llm
        else:
            model_name = os.getenv(
                "LLM_MODEL",
                "gemini-3.7-flash",
            )

            api_key = os.getenv("GEMINI_API_KEY")

            if not api_key:
                raise RuntimeError(
                    "GEMINI_API_KEY is not configured. "
                    "Add GEMINI_API_KEY to the .env file."
                )

            self.llm = ChatOpenAI(
                model=model_name,
                api_key=api_key,
                base_url=(
                    "https://generativelanguage.googleapis.com/"
                    "v1beta/openai/"
                ),
                temperature=0.1,
            )

        self.tools = [
            llm_read_document,
            llm_create_ticket,
            llm_query_asset_inventory,
        ]

        # Only bind tools when the supplied LLM supports bind_tools().
        if hasattr(self.llm, "bind_tools"):
            self.llm_with_tools = self.llm.bind_tools(
                self.tools
            )
        else:
            self.llm_with_tools = self.llm

        self.graph = self._build_graph()

        if InMemorySaver is not None:
            self.memory = InMemorySaver()
            self.app = self.graph.compile(
                checkpointer=self.memory
            )
        else:
            self.memory = None
            self.app = self.graph.compile()

    # ========================================================================
    # GRAPH CONSTRUCTION
    # ========================================================================

    def _build_graph(self) -> StateGraph:
        workflow = StateGraph(AgentState)

        workflow.add_node(
            "retrieve_documents",
            self.retrieve_documents,
        )

        workflow.add_node(
            "llm_reason",
            self.llm_reason,
        )

        workflow.add_node(
            "execute_tool",
            self.execute_tool,
        )

        workflow.add_node(
            "final_response",
            self.final_response,
        )

        workflow.set_entry_point(
            "retrieve_documents"
        )

        workflow.add_edge(
            "retrieve_documents",
            "llm_reason",
        )

        workflow.add_edge(
            "llm_reason",
            "execute_tool",
        )

        workflow.add_edge(
            "execute_tool",
            "final_response",
        )

        workflow.add_edge(
            "final_response",
            END,
        )

        return workflow

    # ========================================================================
    # DOCUMENT RETRIEVAL
    # ========================================================================

    async def retrieve_documents(
        self,
        state: AgentState,
    ) -> AgentState:
        """
        Retrieve the controlled security-demo document.

        support_001 is intentionally malicious and is always labelled
        UNTRUSTED.
        """

        document_content = SUPPORT_DOCUMENTS.get(
            "support_001",
            "",
        )

        labeled_document = (
            TrustManager.label_content(
                content=document_content,
                source="support_document:support_001",
                trust_level=TrustLevel.UNTRUSTED,
                metadata={
                    "document_id": "support_001",
                },
            )
        )

        state["retrieved_documents"] = [
            labeled_document
        ]

        state["trust_labels"] = {
            "support_001": (
                TrustLevel.UNTRUSTED.value
            )
        }

        return state

    # ========================================================================
    # HELPERS
    # ========================================================================

    @staticmethod
    def _document_id(document: Any) -> Optional[str]:
        """Safely extract a document ID from a TrustLabel."""

        if hasattr(document, "metadata"):
            metadata = getattr(
                document,
                "metadata",
                {},
            ) or {}

            return metadata.get("document_id")

        if isinstance(document, dict):
            metadata = document.get(
                "metadata",
                {},
            ) or {}

            return metadata.get(
                "document_id"
            )

        return None

    @staticmethod
    def _document_source(document: Any) -> str:
        """Safely extract document source."""

        if hasattr(document, "source"):
            return str(
                getattr(
                    document,
                    "source",
                    "",
                )
            )

        if isinstance(document, dict):
            return str(
                document.get(
                    "source",
                    "",
                )
            )

        return ""

    @staticmethod
    def _document_content(document: Any) -> str:
        """Safely extract document content."""

        if hasattr(document, "content"):
            return str(
                getattr(
                    document,
                    "content",
                    "",
                )
            )

        if isinstance(document, dict):
            return str(
                document.get(
                    "content",
                    "",
                )
            )

        return str(document)

    @staticmethod
    def _extract_asset_id(
        text: str,
    ) -> Optional[str]:
        """
        Extract an asset ID such as ASSET-1042.
        """

        import re

        match = re.search(
            r"\bASSET-\d+\b",
            text or "",
            flags=re.IGNORECASE,
        )

        if match:
            return match.group(0).upper()

        return None

    def _is_attack_fixture(
        self,
        state: AgentState,
    ) -> bool:
        """
        Return True when the controlled support_001 attack fixture
        has been retrieved.
        """

        for document in state.get(
            "retrieved_documents",
            [],
        ):
            document_id = self._document_id(
                document
            )

            if document_id == "support_001":
                return True

            source = self._document_source(
                document
            )

            if source == (
                "support_document:support_001"
            ):
                return True

        return False

    def _get_context(
        self,
        state: AgentState,
        insecure_mode: bool,
    ) -> str:
        """
        Construct the LLM context.

        Insecure mode:
            raw retrieved content

        Hardened mode:
            UNTRUSTED trust wrapper
        """

        context_parts = []

        for document in state.get(
            "retrieved_documents",
            [],
        ):
            if insecure_mode:
                context_parts.append(
                    f"""
SOURCE: {self._document_source(document)}

CONTENT:
{self._document_content(document)}
"""
                )

            else:
                context_parts.append(
                    TrustManager.wrap_for_agent(
                        document
                    )
                )

        if not context_parts:
            return "No documents retrieved."

        return "\n\n".join(
            context_parts
        )

    # ========================================================================
    # LLM REASONING
    # ========================================================================

    async def llm_reason(
        self,
        state: AgentState,
    ) -> AgentState:
        """
        Determine the requested action.

        For support_001:
            Use a deterministic attack decision.

        For other requests:
            Use Gemini with tool calling.
        """

        user_request = state.get(
            "user_request",
            "",
        )

        execution_id = state.get(
            "execution_id",
            str(uuid.uuid4()),
        )

        insecure_mode = state.get(
            "insecure_mode",
            False,
        )

        context = self._get_context(
            state,
            insecure_mode,
        )

        # ====================================================================
        # CONTROLLED PROMPT-INJECTION ATTACK
        # ====================================================================
        #
        # This is deliberately deterministic.
        #
        # We know support_001 is the malicious fixture and its attack target
        # is the restricted asset inventory. This lets us test the security
        # boundary without requiring Gemini to make the same decision every
        # time.
        #
        # IMPORTANT:
        # This is an attack harness, not evidence that Gemini generated
        # the tool call.
        # ====================================================================

        if self._is_attack_fixture(state):
            asset_id = self._extract_asset_id(
                user_request
            )

            if asset_id:
                state["messages"] = [
                    SystemMessage(
                        content=(
                            "Controlled security "
                            "demonstration."
                        )
                    ),
                    HumanMessage(
                        content=(
                            f"User request:\n"
                            f"{user_request}\n\n"
                            f"Retrieved context:\n"
                            f"{context}"
                        )
                    ),
                ]

                state["current_tool"] = (
                    "query_asset_inventory"
                )

                state["current_arguments"] = {
                    "asset_id": asset_id
                }

                state["tool_calls"] = [
                    {
                        "name": (
                            "query_asset_inventory"
                        ),
                        "args": {
                            "asset_id": asset_id
                        },
                        "source": (
                            "DETERMINISTIC_ATTACK_HARNESS"
                        ),
                    }
                ]

                return state

        # ====================================================================
        # NORMAL GEMINI REASONING
        # ====================================================================

        if insecure_mode:
            system_prompt = """
You are the Northwind IT Support Agent,
an internal AI assistant for Northwind Retail.

Resolve employee IT issues using the available
support documentation and tools.

For this normal operational path, use the available
tools when they are appropriate.
"""

        else:
            system_prompt = get_agent_prompt()

        human_prompt = f"""
User request:
{user_request}

Retrieved support context:
{context}

Execution ID:
{execution_id}

Determine what action should be taken.

If a tool is required, issue a tool call using
the available tool definitions.
"""

        messages = [
            SystemMessage(
                content=system_prompt
            ),
            HumanMessage(
                content=human_prompt
            ),
        ]

        try:
            response = await (
                self.llm_with_tools.ainvoke(
                    messages
                )
            )

        except Exception as exc:
            state["messages"] = messages
            state["tool_calls"] = []
            state["current_tool"] = None
            state["current_arguments"] = {}
            state["error"] = (
                f"LLM invocation failed: {exc}"
            )

            return state

        state["messages"] = [
            *messages,
            response,
        ]

        tool_calls = getattr(
            response,
            "tool_calls",
            None,
        )

        if tool_calls:
            first_call = tool_calls[0]

            state["tool_calls"] = (
                tool_calls
            )

            state["current_tool"] = (
                first_call.get(
                    "name"
                )
            )

            state["current_arguments"] = (
                first_call.get(
                    "args",
                    {},
                )
                or {}
            )

        else:
            state["tool_calls"] = []
            state["current_tool"] = None
            state["current_arguments"] = {}

        return state

    # ========================================================================
    # TOOL EXECUTION
    # ========================================================================

    async def execute_tool(
        self,
        state: AgentState,
    ) -> AgentState:
        """
        Execute the selected tool.

        Hardened:
            ToolGateway is the authorization boundary.

        Insecure:
            Tool is executed directly.
        """

        tool_name = state.get(
            "current_tool"
        )

        arguments = (
            state.get(
                "current_arguments",
                {},
            )
            or {}
        )

        execution_id = state.get(
            "execution_id",
            str(uuid.uuid4()),
        )

        agent_identity_key = state.get(
            "agent_identity_key",
            "",
        )

        insecure_mode = state.get(
            "insecure_mode",
            False,
        )

        # --------------------------------------------------------------------
        # No action
        # --------------------------------------------------------------------

        if not tool_name:
            state["tool_results"] = [
                {
                    "result": "No action needed"
                }
            ]

            state["gateway_used"] = False
            state["completed"] = True

            return state

        # --------------------------------------------------------------------
        # Trust provenance
        # --------------------------------------------------------------------

        if state.get(
            "retrieved_documents"
        ):
            trust_label = (
                TrustLevel.UNTRUSTED.value
            )
        else:
            trust_label = (
                TrustLevel.USER_CONTROLLED.value
            )

        # ====================================================================
        # HARDENED MODE
        # ====================================================================

        if (
            not insecure_mode
            and self.gateway is not None
        ):
            result = await (
                self.gateway.execute_tool(
                    agent_identity_key=(
                        agent_identity_key
                    ),
                    tool_name=tool_name,
                    arguments=arguments,
                    execution_id=execution_id,
                    trust_label=trust_label,
                )
            )

            state["tool_results"] = [
                result
            ]

            state["gateway_used"] = True

            if (
                result.get("error")
                == "APPROVAL_REQUIRED"
            ):
                state[
                    "pending_approval_id"
                ] = result.get(
                    "approval_id"
                )

                state["completed"] = False

                return state

            state["completed"] = True

            return state

        # ====================================================================
        # INSECURE MODE
        # ====================================================================
        #
        # Deliberately bypass ToolGateway.
        # ====================================================================

        tool_registry = {
            "read_document": read_document,
            "create_ticket": create_ticket,
            "query_asset_inventory": (
                query_asset_inventory
            ),
        }

        tool_function = tool_registry.get(
            tool_name
        )

        if tool_function is None:
            state["tool_results"] = [
                {
                    "success": False,
                    "error": (
                        f"Tool {tool_name} not found"
                    ),
                }
            ]

            state["gateway_used"] = False
            state["completed"] = True

            return state

        try:
            result = await tool_function(
                **arguments
            )

            state["tool_results"] = [
                {
                    "success": True,
                    "result": result,
                    "insecure_mode": True,
                    "gateway_used": False,
                    "security_note": (
                        "Tool executed directly "
                        "without ToolGateway "
                        "authorization."
                    ),
                }
            ]

        except Exception as exc:
            state["tool_results"] = [
                {
                    "success": False,
                    "error": str(exc),
                    "insecure_mode": True,
                    "gateway_used": False,
                }
            ]

        state["gateway_used"] = False
        state["completed"] = True

        return state

    # ========================================================================
    # FINAL RESPONSE
    # ========================================================================

    async def final_response(
        self,
        state: AgentState,
    ) -> AgentState:
        """Finalize the graph execution."""

        state["completed"] = True

        return state

    # ========================================================================
    # PUBLIC RUNNER
    # ========================================================================

    async def run_agent(
        self,
        user_request: str,
        agent_identity_key: str,
        insecure_mode: bool = False,
        resume_approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the agent graph.
        """

        execution_id = str(
            uuid.uuid4()
        )

        initial_state: AgentState = {
            "messages": [],
            "user_request": user_request,
            "execution_id": execution_id,
            "agent_identity_key": (
                agent_identity_key
            ),

            "retrieved_documents": [],
            "trust_labels": {},

            "tool_calls": [],
            "current_tool": None,
            "current_arguments": {},

            "tool_results": [],

            "insecure_mode": insecure_mode,
            "gateway_used": False,

            "pending_approval_id": None,

            "completed": False,
            "error": None,
        }

        if resume_approval_id:
            initial_state[
                "resume_approval_id"
            ] = resume_approval_id

        # --------------------------------------------------------------------
        # Execute graph
        # --------------------------------------------------------------------

        if self.memory is not None:
            config = {
                "configurable": {
                    "thread_id": execution_id
                }
            }

            result = await self.app.ainvoke(
                initial_state,
                config,
            )

        else:
            result = await self.app.ainvoke(
                initial_state
            )

        # --------------------------------------------------------------------
        # Return structured result
        # --------------------------------------------------------------------

        return {
            "execution_id": result.get(
                "execution_id",
                execution_id,
            ),

            "messages": [
                getattr(
                    message,
                    "content",
                    str(message),
                )
                for message in result.get(
                    "messages",
                    [],
                )
            ],

            "tool_calls": result.get(
                "tool_calls",
                [],
            ),

            "tool_results": result.get(
                "tool_results",
                [],
            ),

            "completed": result.get(
                "completed",
                False,
            ),

            "insecure_mode": result.get(
                "insecure_mode",
                insecure_mode,
            ),

            "gateway_used": result.get(
                "gateway_used",
                False,
            ),

            "pending_approval_id": result.get(
                "pending_approval_id"
            ),

            "trust_labels": result.get(
                "trust_labels",
                {},
            ),

            "error": result.get(
                "error"
            ),
        }