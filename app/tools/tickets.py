from datetime import datetime, timezone
import uuid
from typing import Any, Dict

tickets: list[Dict[str, Any]] = []


async def create_ticket(title: str, description: str, priority: str = "medium") -> Dict[str, Any]:
    ticket = {
        "ticket_id": str(uuid.uuid4())[:8],
        "title": title,
        "description": description,
        "priority": priority,
        "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    tickets.append(ticket)
    return ticket
