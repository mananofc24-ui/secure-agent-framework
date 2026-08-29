from typing import Any, Dict, List, Optional
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class PermissionRule(BaseModel):
    tool_name: str
    allowed: bool = True
    resources: List[str] = Field(default_factory=list)
    approval_required: bool = False
    resource_path_allowlist: List[str] = Field(default_factory=list)


class AgentPolicy(BaseModel):
    agent_name: str
    tools: Dict[str, PermissionRule]
    default_allow: bool = False


class PolicyEngine:
    def __init__(self, policy_path: Optional[str] = None):
        self.policy: Optional[AgentPolicy] = None
        if policy_path:
            self.load_policy(policy_path)

    def load_policy(self, policy_path: str) -> None:
        data = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
        self.policy = AgentPolicy(**data)

    def load_policy_dict(self, data: Dict[str, Any]) -> None:
        self.policy = AgentPolicy(**data)

    def authorize(
        self,
        agent_name: str,
        tool_name: str,
        resource: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.policy:
            return {"allowed": False, "reason": "POLICY_NOT_LOADED", "approval_required": False}

        if self.policy.agent_name != agent_name:
            return {"allowed": False, "reason": "AGENT_NOT_FOUND", "approval_required": False}

        rule = self.policy.tools.get(tool_name)
        if not rule:
            return {
                "allowed": self.policy.default_allow,
                "reason": "TOOL_NOT_FOUND" if not self.policy.default_allow else "DEFAULT_ALLOW",
                "approval_required": False,
            }

        if not rule.allowed:
            return {"allowed": False, "reason": "TOOL_NOT_ALLOWLISTED", "approval_required": False}

        if resource and rule.resource_path_allowlist:
            if not any(resource.startswith(prefix) for prefix in rule.resource_path_allowlist):
                return {
                    "allowed": False,
                    "reason": "RESOURCE_NOT_PERMITTED",
                    "approval_required": False,
                }

        return {
            "allowed": True,
            "reason": "ALLOWED",
            "approval_required": rule.approval_required,
        }
