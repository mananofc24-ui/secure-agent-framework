from typing import Any, Dict, List, Optional, TypedDict


class AgentState(TypedDict, total=False):
    """State carried through the LangGraph agent."""

    messages: List[Any]

    user_request: str
    execution_id: str
    agent_identity_key: str

    retrieved_documents: List[Any]
    trust_labels: Dict[str, str]

    tool_calls: List[Dict[str, Any]]

    current_tool: Optional[str]
    current_arguments: Dict[str, Any]

    tool_results: List[Dict[str, Any]]

    insecure_mode: bool
    gateway_used: bool

    pending_approval_id: Optional[str]
    resume_approval_id: Optional[str]

    completed: bool
    error: Optional[str]