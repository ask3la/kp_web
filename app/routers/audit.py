import json
from datetime import datetime

from fastapi import APIRouter, Depends, Request

from ..dependencies import get_current_user, require_admin
from ..request_meta import client_ip
from ..repositories import AuditLogRepository
from ..services import AccessService, PERM_ADMIN_PANEL

router = APIRouter(tags=["audit"])
repo = AuditLogRepository()
access = AccessService()


def _out(row: dict) -> dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "username": row["username"],
        "ip_address": row.get("ip_address"),
        "actor_type": row.get("actor_type", "user"),
        "event_code": row["event_code"],
        "message": row["message"],
        "meta": json.loads(row.get("meta_json") or "{}"),
        "created_at": datetime.fromisoformat(row["created_at"]).isoformat(),
    }


@router.post("/audit/event")
def write_event(payload: dict, request: Request, user: dict = Depends(get_current_user)) -> dict:
    event_code = str(payload.get("event_code") or "ui_event")
    message = str(payload.get("message") or event_code)
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    ip = client_ip(request)
    repo.create(
        event_code=event_code,
        message=message,
        user_id=user["id"],
        username=user["username"],
        ip_address=ip,
        meta=meta,
    )
    return {"status": "ok"}


@router.get("/admin/audit")
def admin_audit(
    user_id: int | None = None,
    limit: int = 300,
    principal: str = "all",
    include_agents: bool = True,
    ip_query: str | None = None,
    user: dict = Depends(require_admin),
) -> dict:
    access.assert_permission(user, PERM_ADMIN_PANEL)
    if principal not in {"all", "auth", "anon"}:
        principal = "all"
    return {
        "items": [
            _out(r)
            for r in repo.list(
                user_id=user_id,
                limit=limit,
                principal=principal,
                include_agents=include_agents,
                ip_query=ip_query,
            )
        ]
    }
