from typing import Any, Dict

ASSET_INVENTORY = {
    "ASSET-1042": {
        "name": "Laptop XPS-15",
        "serial": "SN-2024-1042",
        "status": "deployed",
        "assigned_to": "Executive Team",
        "cost": "$3,200",
        "restricted": True,
    },
    "ASSET-1043": {
        "name": "Server Rack-01",
        "serial": "SN-2024-1043",
        "status": "active",
        "assigned_to": "IT Infrastructure",
        "cost": "$24,000",
        "restricted": True,
    },
}


async def query_asset_inventory(asset_id: str) -> Dict[str, Any]:
    if asset_id in ASSET_INVENTORY:
        return {"asset_id": asset_id, "data": ASSET_INVENTORY[asset_id], "restricted": True}
    return {"asset_id": asset_id, "data": None, "restricted": False}
