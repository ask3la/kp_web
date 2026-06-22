from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from ..dependencies import get_current_user, require_admin
from ..models import VolumeCreate, VolumeOut, VolumeUpdate
from ..repositories import FileRepository, VolumeRepository
from ..services import AccessService, PERM_MANAGE_VOLUMES, ProvisioningService

router = APIRouter(prefix="/volumes", tags=["volumes"])
repo = VolumeRepository()
files = FileRepository()
provision = ProvisioningService()
access = AccessService()


def _to_model(row: dict) -> VolumeOut:
    return VolumeOut(
        id=row["id"],
        node_id=row["node_id"],
        mount_path=row["mount_path"],
        label=row["label"],
        quota_gb=row["quota_gb"],
        quota_bytes=int(row.get("quota_bytes") or (int(row["quota_gb"]) * 1024 * 1024 * 1024)),
        used_gb=row["used_gb"],
        used_bytes=row.get("used_bytes", 0),
        is_active=bool(row["is_active"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


@router.post("", response_model=VolumeOut)
def create_volume(payload: VolumeCreate, user: dict = Depends(require_admin)) -> VolumeOut:
    access.assert_permission(user, PERM_MANAGE_VOLUMES)
    return _to_model(
        provision.provision_volume(
            node_id=payload.node_id,
            mount_path=payload.mount_path,
            quota_bytes=payload.quota_bytes,
            label=payload.label,
        )
    )


@router.get("", response_model=list[VolumeOut])
def list_volumes(node_id: int | None = None, _: dict = Depends(get_current_user)) -> list[VolumeOut]:
    return [_to_model(v) for v in repo.list_volumes(node_id=node_id)]


@router.put("/{volume_id}", response_model=VolumeOut)
def update_volume(volume_id: int, payload: VolumeUpdate, user: dict = Depends(require_admin)) -> VolumeOut:
    access.assert_permission(user, PERM_MANAGE_VOLUMES)
    changed = {k: v for k, v in payload.model_dump().items() if v is not None}
    volume = repo.update(volume_id=volume_id, data=changed)
    if not volume:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found")
    return _to_model(volume)


@router.delete("/{volume_id}")
def delete_volume(volume_id: int, user: dict = Depends(require_admin)) -> dict:
    access.assert_permission(user, PERM_MANAGE_VOLUMES)
    linked_files = [f for f in files.list_files() if f["volume_id"] == volume_id]
    if linked_files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Volume has files ({len(linked_files)}). Delete files first.",
        )
    deleted = repo.delete(volume_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Volume not found")
    return {"status": "deleted"}
