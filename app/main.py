import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, select
from dotenv import load_dotenv

from app.audit.logger import AuditLogger
from app.db.database import get_db, init_db
from app.db.models import AuditLog, TrustLevel
from app.security.approval import ApprovalManager
from app.security.credentials import CredentialManager
from app.security.gateway import ToolGateway
from app.security.identity import IdentityManager
from app.security.policy import PolicyEngine
from app.security.revocation import RevocationManager
from app.agent.graph import AgentGraph
from app.tools.assets import query_asset_inventory
from app.tools.documents import read_document
from app.tools.tickets import create_ticket


load_dotenv()


TOOL_REGISTRY = {
    "read_document": read_document,
    "create_ticket": create_ticket,
    "query_asset_inventory": query_asset_inventory,
}


BASE_DIR = Path(__file__).resolve().parent.parent

HARDENED_POLICY_PATH = (
    BASE_DIR / "policies" / "hardened.yaml"
)

ADMIN_API_KEY = os.getenv(
    "ADMIN_API_KEY",
    "change-me-in-production",
)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:8000",
    ).split(",")
    if origin.strip()
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    try:
        yield
    finally:
        await RevocationManager.close_redis()


app = FastAPI(
    title="Secure Agentic AI Framework",
    description=(
        "Security framework for agentic AI with "
        "tool gateway, HITL, and audit logging"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-API-Key"],
)


def verify_admin(api_key: str = Header(..., alias="X-Admin-API-Key")) -> bool:
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    return True


@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "secure-agent-framework"}


@app.post("/api/agent/create")
async def create_agent(name: str, description: str = "", db=Depends(get_db)):
    agent = await IdentityManager.create_agent(db, name, description)
    return {
        "agent_id": str(agent.id),
        "name": agent.name,
        "identity_key": getattr(agent, "_raw_key", None),
        "status": agent.status.value,
    }


@app.post("/api/agent/run")
async def run_agent(
    request: Request,
    user_request: str,
    agent_identity_key: str,
    insecure_mode: bool = False,
    db=Depends(get_db),
):
    agent = await IdentityManager.verify_agent(db, agent_identity_key)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent identity")

    if not insecure_mode and await RevocationManager.is_revoked(db, agent.id):
        raise HTTPException(status_code=403, detail="Agent has been revoked")

    execution_id = str(uuid.uuid4())
    audit = AuditLogger(db)
    await audit.log_agent_request(agent.id, user_request, execution_id)

    gateway = None
    if not insecure_mode:
        policy_engine = PolicyEngine(str(HARDENED_POLICY_PATH))
        gateway = ToolGateway(db, policy_engine, TOOL_REGISTRY)

    graph = AgentGraph(gateway=gateway)
    result = await graph.run_agent(
        user_request=user_request,
        agent_identity_key=agent_identity_key,
        insecure_mode=insecure_mode,
    )

    if result.get("gateway_used"):
        await audit.log_event(
            event_type="SECURITY_GATEWAY_ENFORCED",
            agent_id=agent.id,
            details={
                "execution_id": execution_id,
                "insecure_mode": insecure_mode,
                "tool_results": result.get("tool_results", []),
                "client_ip": request.client.host if request.client else None,
            },
        )

    return {
        "execution_id": execution_id,
        "agent_id": str(agent.id),
        "insecure_mode": insecure_mode,
        "gateway_used": result.get("gateway_used", False),
        "result": result,
    }


@app.post("/api/agent/revoke/{agent_id}")
async def revoke_agent(
    agent_id: str,
    reason: str = "Manual revocation",
    _: bool = Depends(verify_admin),
    db=Depends(get_db),
):
    try:
        agent_uuid = uuid.UUID(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid agent ID") from exc

    result = await RevocationManager.revoke_agent(db, agent_uuid, reason)
    if not result:
        raise HTTPException(status_code=404, detail="Agent not found")

    await AuditLogger(db).log_event(
        event_type="AGENT_REVOKED",
        agent_id=agent_uuid,
        details={"reason": reason},
    )
    return {"success": True, "message": f"Agent {agent_id} revoked"}


@app.post("/api/agent/restore/{agent_id}")
async def restore_agent(
    agent_id: str,
    _: bool = Depends(verify_admin),
    db=Depends(get_db),
):
    try:
        agent_uuid = uuid.UUID(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid agent ID") from exc

    result = await RevocationManager.restore_agent(db, agent_uuid)
    if not result:
        raise HTTPException(status_code=404, detail="Agent not found")

    await AuditLogger(db).log_event(event_type="AGENT_RESTORED", agent_id=agent_uuid)
    return {"success": True, "message": f"Agent {agent_id} restored"}


@app.post("/api/approval/resolve")
async def resolve_approval(
    approval_id: str,
    approved: bool,
    approver: str = "admin",
    _: bool = Depends(verify_admin),
    db=Depends(get_db),
):
    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid approval ID") from exc

    result = await ApprovalManager.resolve_approval(db, approval_uuid, approved, approver)
    if not result:
        raise HTTPException(status_code=404, detail="Approval not found or expired")

    await AuditLogger(db).log_event(
        event_type="APPROVAL_RESOLVED",
        agent_id=result.agent_id,
        details={
            "approval_id": str(result.id),
            "approved": approved,
            "approver": approver,
        },
    )
    return {
        "success": True,
        "status": result.status.value,
        "approval_id": str(result.id),
    }


@app.post("/api/approval/resume")
async def resume_after_approval(
    approval_id: str,
    agent_identity_key: str,
    db=Depends(get_db),
):
    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid approval ID") from exc

    approval = await ApprovalManager.get_approval(db, approval_uuid)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.status.value != "approved":
        raise HTTPException(status_code=403, detail="Approval not granted")

    agent_identity = await IdentityManager.verify_agent(db, agent_identity_key)
    if not agent_identity or agent_identity.id != approval.agent_id:
        raise HTTPException(status_code=403, detail="Approval does not belong to this agent")

    if await RevocationManager.is_revoked(db, approval.agent_id):
        raise HTTPException(status_code=403, detail="Agent has been revoked")

    policy_engine = PolicyEngine(str(HARDENED_POLICY_PATH))
    gateway = ToolGateway(db, policy_engine, TOOL_REGISTRY)
    raw_cred, _ = await CredentialManager.issue_credential(
        db,
        agent_id=approval.agent_id,
        scopes=[f"tool:{approval.tool_name}"],
        ttl_minutes=5,
    )

    result = await gateway.execute_tool(
        agent_identity_key=agent_identity_key,
        tool_name=approval.tool_name,
        arguments=approval.arguments or {},
        execution_id=approval.request_id,
        credential_key=raw_cred,
        trust_label=TrustLevel.USER_CONTROLLED.value,
    )

    await AuditLogger(db).log_event(
        event_type="APPROVAL_RESUMED",
        agent_id=approval.agent_id,
        details={
            "approval_id": str(approval.id),
            "tool_name": approval.tool_name,
            "result": result,
        },
    )
    return {"success": result.get("success", False), "result": result}


@app.get("/api/audit/logs")
async def get_audit_logs(limit: int = 100, db=Depends(get_db)):
    safe_limit = max(1, min(limit, 500))
    result = await db.execute(
        select(AuditLog).order_by(desc(AuditLog.created_at)).limit(safe_limit)
    )
    logs = result.scalars().all()
    return [
        {
            "id": log.id,
            "event_type": log.event_type,
            "agent_id": str(log.agent_id) if log.agent_id else None,
            "details": log.details,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]
