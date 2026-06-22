from datetime import datetime
from pathlib import Path
import secrets
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, StreamingResponse

from ..config import SMALL_FILE_THRESHOLD_BYTES, TEMP_DIR
from ..dependencies import get_current_user
from ..download_proxy import broker
from ..models import FileCreate, FileOut, FileUpdate
from ..request_meta import client_ip
from ..repositories import AuditLogRepository, FileRepository, TransferBlobRepository
from ..services import FileService

router = APIRouter(prefix="/files", tags=["files"])
public_router = APIRouter(tags=["files"])
repo = FileRepository()
service = FileService()
blobs = TransferBlobRepository()
audit = AuditLogRepository()


def _to_model(row: dict) -> FileOut:
    return FileOut(
        id=row["id"],
        file_name=row["file_name"],
        logical_path=row["logical_path"],
        size_mb=row["size_mb"],
        owner_id=row["owner_id"],
        node_id=row["node_id"],
        volume_id=row["volume_id"],
        resource_id=row["resource_id"],
        status=row["status"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


def _new_share_uuid() -> str:
    # 192 random bytes => 256 url-safe characters.
    return secrets.token_urlsafe(192)


@router.post("", response_model=FileOut)
def create_file(payload: FileCreate, request: Request, user: dict = Depends(get_current_user)) -> FileOut:
    row = service.create_file(
        user=user,
        file_name=payload.file_name,
        logical_path=payload.logical_path,
        size_mb=payload.size_mb,
        resource_id=payload.resource_id,
    )
    audit.create(
        event_code="file_create",
        message=f"Created file record {payload.file_name}",
        user_id=user["id"],
        username=user["username"],
        ip_address=client_ip(request),
        meta={"resource_id": payload.resource_id, "logical_path": payload.logical_path, "file_id": row["id"]},
    )
    return _to_model(row)


@router.post("/upload", response_model=FileOut)
async def upload_file(
    request: Request,
    resource_id: int = Form(...),
    logical_path: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
) -> FileOut:
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)
    target = Path(TEMP_DIR) / f"upload_{datetime.now().timestamp()}_{file.filename or 'file.bin'}"
    size_bytes = 0
    with target.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size_bytes += len(chunk)
            out.write(chunk)
    if size_bytes == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")
    row = service.create_uploaded_file(
        user=user,
        resource_id=resource_id,
        logical_path=logical_path,
        file_name=file.filename or "uploaded.bin",
        temp_path=target,
        size_bytes=size_bytes,
    )
    audit.create(
        event_code="file_upload",
        message=f"Uploaded file {file.filename or 'uploaded.bin'}",
        user_id=user["id"],
        username=user["username"],
        ip_address=client_ip(request),
        meta={"resource_id": resource_id, "logical_path": logical_path, "file_id": row["id"], "size_bytes": size_bytes},
    )
    return _to_model(row)


@router.get("", response_model=list[FileOut])
def list_files(user: dict = Depends(get_current_user)) -> list[FileOut]:
    rows = repo.list_files()
    visible = [r for r in rows if service.can_read_file(user, r)]
    return [_to_model(r) for r in visible]


@router.get("/{file_id}", response_model=FileOut)
def get_file(file_id: int, user: dict = Depends(get_current_user)) -> FileOut:
    existing = repo.get_by_id(file_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if not service.can_read_file(user, existing):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return _to_model(existing)


@router.post("/{file_id}/prepare-download")
def prepare_download(file_id: int, user: dict = Depends(get_current_user)) -> dict:
    return service.request_download_from_agent(user=user, file_id=file_id)


@router.get("/{file_id}/download")
def download(file_id: int, request: Request, user: dict = Depends(get_current_user)):
    existing = repo.get_by_id(file_id)
    if not existing:
        raise HTTPException(status_code=404, detail="File not found")
    if not service.can_read_file(user, existing):
        raise HTTPException(status_code=403, detail="Access denied")
    audit.create(
        event_code="file_download",
        message=f"Download requested for file {existing['file_name']}",
        user_id=user["id"],
        username=user["username"],
        ip_address=client_ip(request),
        meta={"file_id": file_id, "resource_id": existing["resource_id"]},
    )
    proxy_token = str(uuid.uuid4())
    broker.open(proxy_token)
    service.request_download_from_agent(user=user, file_id=file_id, proxy_token=proxy_token)
    return StreamingResponse(
        broker.stream(proxy_token),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{existing["file_name"]}"'},
    )


@router.get("/{file_id}/share")
def get_share_settings(file_id: int, user: dict = Depends(get_current_user)) -> dict:
    existing = repo.get_by_id(file_id)
    if not existing:
        raise HTTPException(status_code=404, detail="File not found")
    if not service.can_write_file(user, existing):
        raise HTTPException(status_code=403, detail="Access denied")
    enabled = bool(existing.get("share_enabled"))
    share_uuid = existing.get("share_uuid") if enabled else None
    return {"file_id": file_id, "enabled": enabled, "share_uuid": share_uuid}


@router.put("/{file_id}/share")
def update_share_settings(file_id: int, payload: dict, request: Request, user: dict = Depends(get_current_user)) -> dict:
    existing = repo.get_by_id(file_id)
    if not existing:
        raise HTTPException(status_code=404, detail="File not found")
    if not service.can_write_file(user, existing):
        raise HTTPException(status_code=403, detail="Access denied")

    enabled = bool(payload.get("enabled", False))
    share_uuid = existing.get("share_uuid")
    if enabled:
        if not share_uuid or len(str(share_uuid)) < 256:
            while True:
                candidate = _new_share_uuid()
                if len(candidate) < 256:
                    candidate = (candidate + secrets.token_urlsafe(32))[:256]
                if not repo.has_share_uuid(candidate):
                    share_uuid = candidate
                    break
    else:
        share_uuid = None

    updated = repo.update_share_settings(file_id=file_id, share_enabled=enabled, share_uuid=share_uuid)
    audit.create(
        event_code="file_share_update",
        message=f"{'Enabled' if enabled else 'Disabled'} sharing for file {existing['file_name']}",
        user_id=user["id"],
        username=user["username"],
        ip_address=client_ip(request),
        meta={"file_id": file_id, "resource_id": existing["resource_id"], "enabled": enabled},
    )
    return {
        "file_id": file_id,
        "enabled": bool(updated.get("share_enabled")),
        "share_uuid": updated.get("share_uuid") if bool(updated.get("share_enabled")) else None,
    }


@router.put("/{file_id}", response_model=FileOut)
def update_file(file_id: int, payload: FileUpdate, user: dict = Depends(get_current_user)) -> FileOut:
    existing = repo.get_by_id(file_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if not service.can_write_file(user, existing):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    changed = {k: v for k, v in payload.model_dump().items() if v is not None}
    updated = repo.update(file_id=file_id, data=changed)
    return _to_model(updated)


@router.delete("/{file_id}")
def delete_file(file_id: int, request: Request, user: dict = Depends(get_current_user)) -> dict:
    existing = repo.get_by_id(file_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if not service.can_delete_file(user, existing):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    service.delete_file(file_id=file_id)
    audit.create(
        event_code="file_delete",
        message=f"Deleted file {existing['file_name']}",
        user_id=user["id"],
        username=user["username"],
        ip_address=client_ip(request),
        meta={"file_id": file_id, "resource_id": existing["resource_id"]},
    )
    return {"status": "deleted"}


@public_router.get("/private/{share_uuid}/download")
def download_by_private_link(share_uuid: str, request: Request):
    existing = repo.get_by_share_uuid(share_uuid)
    if not existing:
        raise HTTPException(status_code=404, detail="Shared file not found")
    if len(share_uuid) < 128:
        raise HTTPException(status_code=404, detail="Shared file not found")
    audit.create(
        event_code="file_private_download",
        message=f"Private link download requested for file {existing['file_name']}",
        ip_address=client_ip(request),
        actor_type="anonymous",
        meta={"file_id": existing["id"], "resource_id": existing["resource_id"]},
    )
    proxy_token = str(uuid.uuid4())
    broker.open(proxy_token)
    # Super-admin context bypasses ACL check for dedicated private links.
    service.request_download_from_agent(user={"id": 0, "admin_level": "super_admin"}, file_id=int(existing["id"]), proxy_token=proxy_token)
    return StreamingResponse(
        broker.stream(proxy_token),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{existing["file_name"]}"'},
    )
