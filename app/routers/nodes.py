from datetime import datetime
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, status

from ..dependencies import get_current_user, require_admin
from ..models import ConnectionCheckResult, NodeCreate, NodeOut, NodeUpdate
from ..config import AGENT_REGISTRATION_TOKEN
from ..openpgp_utils import server_public_key_text
from ..repositories import NodeRepository
from ..services import AccessService, NodeService, PERM_MANAGE_NODES

router = APIRouter(prefix="/nodes", tags=["nodes"])
repo = NodeRepository()
node_service = NodeService()
access = AccessService()


def _to_model(row: dict) -> NodeOut:
    return NodeOut(
        id=row["id"],
        name=row["name"],
        host=row["host"],
        port=row["port"],
        connection_type=row["connection_type"],
        agent_url=row["agent_url"],
        ssh_username=row["ssh_username"],
        ssh_key_path=row["ssh_key_path"],
        has_agent_public_key=bool(row.get("agent_public_key")),
        storage_priority=int(row.get("storage_priority", 0)),
        store_all_data=bool(row.get("store_all_data", 0)),
        is_active=bool(row["is_active"]),
        last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
        created_at=datetime.fromisoformat(row["created_at"]),
    )


@router.post("", response_model=NodeOut)
def create_node(payload: NodeCreate, user: dict = Depends(require_admin)) -> NodeOut:
    access.assert_permission(user, PERM_MANAGE_NODES)
    if payload.connection_type == "agent" and not payload.agent_url:
        payload.agent_url = "agent://polling"
    if payload.connection_type == "ssh":
        if not payload.ssh_username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ssh_username is required for ssh mode")
        if not (payload.ssh_key_path or payload.ssh_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="For ssh mode provide ssh_key_path (recommended) or ssh_password",
            )
    return _to_model(repo.create(payload.model_dump()))


@router.post("/agent/register")
def register_agent_node(
    payload: dict,
    x_agent_registration_token: str | None = Header(default=None),
) -> dict:
    if x_agent_registration_token != AGENT_REGISTRATION_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent registration token")
    required = ("name", "host", "port", "agent_url", "agent_public_key")
    if any(k not in payload or not payload[k] for k in required):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Required fields: {required}")
    node = repo.upsert_agent_node(
        name=str(payload["name"]),
        host=str(payload["host"]),
        port=int(payload["port"]),
        agent_url=str(payload.get("agent_url") or "agent://polling"),
        agent_public_key=str(payload["agent_public_key"]),
    )
    if not node.get("agent_token"):
        node = repo.update(node["id"], {"agent_token": secrets.token_urlsafe(32)})
    return {"node_id": node["id"], "agent_token": node["agent_token"], "server_public_key": server_public_key_text()}


@router.get("", response_model=list[NodeOut])
def list_nodes(_: dict = Depends(get_current_user)) -> list[NodeOut]:
    return [_to_model(n) for n in repo.list_nodes()]


@router.put("/{node_id}", response_model=NodeOut)
def update_node(node_id: int, payload: NodeUpdate, user: dict = Depends(require_admin)) -> NodeOut:
    access.assert_permission(user, PERM_MANAGE_NODES)
    changed = {k: v for k, v in payload.model_dump().items() if v is not None}
    node = repo.update(node_id=node_id, data=changed)
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return _to_model(node)


@router.post("/{node_id}/check", response_model=ConnectionCheckResult)
def check_node_connection(node_id: int, user: dict = Depends(require_admin)) -> ConnectionCheckResult:
    access.assert_permission(user, PERM_MANAGE_NODES)
    ok, message = node_service.check_connection(node_id=node_id)
    return ConnectionCheckResult(node_id=node_id, ok=ok, message=message)


@router.delete("/{node_id}")
def delete_node(node_id: int, user: dict = Depends(require_admin)) -> dict:
    access.assert_permission(user, PERM_MANAGE_NODES)
    try:
        deleted = repo.delete(node_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete node: {exc}",
        ) from exc
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return {"status": "deleted"}
