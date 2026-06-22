import json
import secrets
from pathlib import Path

from fastapi import APIRouter, File, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse

from ..config import AGENT_REGISTRATION_TOKEN, TEMP_DIR
from ..download_proxy import broker
from ..openpgp_utils import decrypt_json_with_private_key, encrypt_json_for_public_key, load_server_private_key, server_public_key_text
from ..repositories import AgentJobRepository, NodeRepository, TransferBlobRepository, VolumeRepository
from ..services import FileService

router = APIRouter(prefix="/agent/control", tags=["agent_control"])
nodes = NodeRepository()
jobs = AgentJobRepository()
blobs = TransferBlobRepository()
volumes = VolumeRepository()
file_service = FileService()


def _agent_node(x_agent_token: str | None = Header(default=None)) -> dict:
    if not x_agent_token:
        raise HTTPException(status_code=401, detail="Missing X-Agent-Token")
    node = nodes.get_by_agent_token(x_agent_token)
    if not node:
        raise HTTPException(status_code=401, detail="Invalid X-Agent-Token")
    return node


@router.post("/register")
def register(payload: dict, x_agent_registration_token: str | None = Header(default=None)) -> dict:
    if x_agent_registration_token != AGENT_REGISTRATION_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid registration token")
    required = ("name", "host", "port", "agent_public_key")
    if any(not payload.get(k) for k in required):
        raise HTTPException(status_code=400, detail=f"Required fields: {required}")
    node = nodes.upsert_agent_node(
        name=str(payload["name"]),
        host=str(payload["host"]),
        port=int(payload["port"]),
        agent_url=str(payload.get("agent_url") or "agent://polling"),
        agent_public_key=str(payload["agent_public_key"]),
    )
    if not node.get("agent_token"):
        node = nodes.update(node["id"], {"agent_token": secrets.token_urlsafe(32)})
    return {
        "node_id": node["id"],
        "agent_token": node["agent_token"],
        "server_public_key": server_public_key_text(),
    }


@router.post("/heartbeat")
def heartbeat(payload: dict, x_agent_token: str | None = Header(default=None)) -> dict:
    node = _agent_node(x_agent_token)
    nodes.set_heartbeat(node["id"], payload.get("os_type"), payload.get("disks", []))
    volumes.sync_used_space_for_node(node_id=node["id"], mounts_meta=payload.get("volumes", []))
    sync_stats = file_service.sync_from_agent_volume_meta(node_id=node["id"], volumes_meta=payload.get("volumes", []))
    return {"ok": True, "sync": sync_stats}


@router.post("/jobs/fetch")
def fetch_job(x_agent_token: str | None = Header(default=None)) -> dict:
    node = _agent_node(x_agent_token)
    job = jobs.fetch_next_for_node(node["id"])
    if not job:
        return {"ok": True, "job": None}
    if not node.get("agent_public_key"):
        raise HTTPException(status_code=400, detail="Node has no agent public key")
    payload = json.loads(job["payload_json"])
    encrypted = encrypt_json_for_public_key(node["agent_public_key"], payload)
    return {"ok": True, "job": {"id": job["id"], "job_type": job["job_type"], "payload_encrypted": encrypted}}


@router.get("/jobs/{job_id}/download")
def download_job_blob(job_id: int, x_agent_token: str | None = Header(default=None)):
    node = _agent_node(x_agent_token)
    job = jobs.get_by_id(job_id)
    if not job or job["node_id"] != node["id"]:
        raise HTTPException(status_code=404, detail="Job not found")
    payload = json.loads(job["payload_json"])
    blob = blobs.get_by_id(int(payload.get("blob_id", 0)))
    if not blob:
        raise HTTPException(status_code=404, detail="Blob not found")
    return FileResponse(path=blob["local_path"], filename=Path(blob["local_path"]).name)


@router.post("/jobs/{job_id}/upload-result")
async def upload_job_result(job_id: int, file: UploadFile = File(...), x_agent_token: str | None = Header(default=None)) -> dict:
    node = _agent_node(x_agent_token)
    job = jobs.get_by_id(job_id)
    if not job or job["node_id"] != node["id"]:
        raise HTTPException(status_code=404, detail="Job not found")
    payload = json.loads(job["payload_json"])
    file_id = int(payload.get("file_id", 0))
    proxy_token = payload.get("proxy_token")
    if proxy_token:
        size = 0
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if not broker.push(str(proxy_token), chunk):
                    break
            broker.complete(str(proxy_token))
            return {"ok": True, "size_bytes": size, "proxied": True}
        except Exception as exc:
            broker.fail(str(proxy_token), str(exc))
            raise

    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)
    target = Path(TEMP_DIR) / f"download_{job_id}_{file.filename or 'file.bin'}"
    content = await file.read()
    target.write_bytes(content)
    blob = blobs.create(file_id=file_id, direction="from_agent", node_id=node["id"], local_path=str(target), size_bytes=len(content))
    return {"ok": True, "blob_id": blob["id"], "size_bytes": len(content)}


@router.post("/jobs/{job_id}/complete")
def complete_job(job_id: int, payload: dict, x_agent_token: str | None = Header(default=None)) -> dict:
    node = _agent_node(x_agent_token)
    job = jobs.get_by_id(job_id)
    if not job or job["node_id"] != node["id"]:
        raise HTTPException(status_code=404, detail="Job not found")
    if "encrypted_result" in payload:
        decoded = decrypt_json_with_private_key(load_server_private_key(), payload["encrypted_result"])
        ok = bool(decoded.get("ok", False))
        result = decoded.get("result", {})
    else:
        ok = bool(payload.get("ok", False))
        result = payload.get("result", {})
    file_service.mark_job_result(job_id, ok, result if isinstance(result, dict) else {"raw": str(result)})
    return {"ok": True}
