from pathlib import Path
import time

from fastapi import FastAPI, Request
from fastapi.responses import Response

from .config import FILES_DIR, TEMP_DIR
from .routers.admin import router as admin_router
from .routers.agent_control import router as agent_control_router
from .routers.audit import router as audit_router
from .db import init_db
from .openpgp_utils import ensure_server_keypair
from .routers.acl import router as acl_router
from .routers.auth import router as auth_router
from .routers.files import public_router as files_public_router, router as files_router
from .routers.nodes import router as nodes_router
from .routers.volumes import router as volumes_router
from .request_meta import client_ip, client_user_agent
from .repositories import AuditLogRepository, NodeRepository, UserRepository
from .security import decode_access_token
from .seed import seed_if_empty

app = FastAPI(
    title="CoStor - Corporate Cloud Storage Control API",
    version="2.0.0",
    description="Control-plane service for users/clients/admins, storage nodes, volume provisioning and file metadata",
)
audit_repo = AuditLogRepository()
users_repo = UserRepository()
nodes_repo = NodeRepository()


def _parse_actor(request: Request) -> tuple[str, int | None, str | None]:
    agent_token = request.headers.get("x-agent-token")
    if agent_token:
        node = nodes_repo.get_by_agent_token(agent_token)
        if node:
            return "agent", None, f"agent:{node.get('name') or node['id']}"

    auth_header = request.headers.get("authorization") or ""
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token:
            try:
                payload = decode_access_token(token)
                user = users_repo.get_by_id(int(payload.get("sub", 0)))
                if user and not bool(user.get("is_blocked")):
                    return "user", int(user["id"]), str(user["username"])
            except Exception:
                pass
    return "anonymous", None, "anonymous"


@app.middleware("http")
async def audit_all_requests(request: Request, call_next):
    started = time.perf_counter()
    actor_type, user_id, username = _parse_actor(request)
    status_code = 500
    response: Response | None = None
    exc_message: str | None = None
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    except Exception as exc:
        exc_message = str(exc)
        raise
    finally:
        duration_ms = int((time.perf_counter() - started) * 1000)
        ip = client_ip(request)
        path = request.url.path
        query = request.url.query
        try:
            audit_repo.create(
                event_code="http_request",
                message=f"{request.method} {path} -> {status_code}",
                user_id=user_id,
                username=username,
                ip_address=ip,
                actor_type=actor_type,
                meta={
                    "method": request.method,
                    "path": path,
                    "query": query,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "user_agent": client_user_agent(request),
                    "error": exc_message,
                },
            )
        except Exception:
            pass


@app.on_event("startup")
def on_startup() -> None:
    Path(FILES_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)
    ensure_server_keypair()
    init_db()
    seed_if_empty()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(acl_router)
app.include_router(agent_control_router)
app.include_router(audit_router)
app.include_router(admin_router)
app.include_router(nodes_router)
app.include_router(volumes_router)
app.include_router(files_router)
app.include_router(files_public_router)
