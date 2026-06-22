from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from ..dependencies import get_current_user, require_admin
from ..models import (
    GroupCreate,
    GroupOut,
    PermissionGrant,
    PermissionOut,
    ResourceFolderCreate,
    ResourceFolderOut,
    ResourceCreate,
    ResourceUpdate,
    ResourceOut,
    UserGroupBind,
)
from ..repositories import GroupRepository, NodeRepository, PermissionRepository, ResourceNodeRepository, ResourceRepository, UserGroupRepository, UserRepository
from ..services import ACLService, PERM_MANAGE_PERMISSIONS, PERM_MANAGE_USERS

router = APIRouter(prefix="/acl", tags=["acl"])
acl = ACLService()


def _group_out(row: dict) -> GroupOut:
    return GroupOut(
        id=row["id"],
        name=row["name"],
        code=row["code"],
        group_type=row["group_type"],
        parent_id=row["parent_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _resource_out(row: dict) -> ResourceOut:
    return ResourceOut(
        id=row["id"],
        name=row["name"],
        code=row["code"],
        path=row["path"],
        resource_type=row["resource_type"],
        size_limit_mb=int(row.get("size_limit_mb", 0)),
        parent_id=row["parent_id"],
        is_hidden=bool(row["is_hidden"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _perm_out(row: dict) -> PermissionOut:
    return PermissionOut(
        id=row["id"],
        group_id=row["group_id"],
        resource_id=row["resource_id"],
        permission_code=row["permission_code"],
        allow=bool(row["allow"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _folder_out(row: dict) -> ResourceFolderOut:
    return ResourceFolderOut(
        id=row["id"],
        resource_id=row["resource_id"],
        folder_path=row["folder_path"],
        created_by=row["created_by"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


@router.post("/groups", response_model=GroupOut)
def create_group(payload: GroupCreate, user: dict = Depends(require_admin)) -> GroupOut:
    return _group_out(
        acl.create_group(
            actor=user,
            name=payload.name,
            code=payload.code,
            group_type=payload.group_type,
            parent_id=payload.parent_id,
        )
    )


@router.get("/groups", response_model=list[GroupOut])
def list_groups(_: dict = Depends(get_current_user)) -> list[GroupOut]:
    return [_group_out(r) for r in GroupRepository().list_groups()]


@router.delete("/groups/{group_id}")
def delete_group(group_id: int, user: dict = Depends(require_admin)) -> dict:
    deleted = acl.delete_group(actor=user, group_id=group_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return {"status": "deleted"}


@router.post("/groups/bind-user")
def bind_user(payload: UserGroupBind, user: dict = Depends(require_admin)) -> dict:
    acl.bind_user_group(actor=user, user_id=payload.user_id, group_id=payload.group_id)
    return {"status": "ok"}


@router.delete("/groups/{group_id}/users/{user_id}")
def unbind_user(group_id: int, user_id: int, user: dict = Depends(require_admin)) -> dict:
    acl.access.assert_permission(user, PERM_MANAGE_USERS)
    if not acl.access.can_manage_group(user, group_id):
        raise HTTPException(status_code=403, detail="Out of admin scope")
    UserGroupRepository().unbind(user_id=user_id, group_id=group_id)
    return {"status": "ok"}


@router.post("/resources", response_model=ResourceOut)
def create_resource(payload: ResourceCreate, user: dict = Depends(require_admin)) -> ResourceOut:
    return _resource_out(acl.create_resource(actor=user, payload=payload.model_dump()))


@router.put("/resources/{resource_id}", response_model=ResourceOut)
def update_resource(resource_id: int, payload: ResourceUpdate, user: dict = Depends(require_admin)) -> ResourceOut:
    return _resource_out(acl.update_resource(actor=user, resource_id=resource_id, payload=payload.model_dump()))


@router.delete("/resources/{resource_id}")
def delete_resource(resource_id: int, user: dict = Depends(require_admin)) -> dict:
    acl.access.assert_permission(user, PERM_MANAGE_PERMISSIONS)
    try:
        deleted = ResourceRepository().delete(resource_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Cannot delete resource: {exc}") from exc
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return {"status": "deleted"}


@router.post("/folders", response_model=ResourceFolderOut)
def create_folder(payload: ResourceFolderCreate, user: dict = Depends(get_current_user)) -> ResourceFolderOut:
    return _folder_out(acl.create_folder(actor=user, resource_id=payload.resource_id, folder_path=payload.folder_path))


@router.get("/resources/{resource_id}/folders", response_model=list[ResourceFolderOut])
def list_folders(resource_id: int, user: dict = Depends(get_current_user)) -> list[ResourceFolderOut]:
    return [_folder_out(r) for r in acl.list_folders(actor=user, resource_id=resource_id)]


@router.get("/resources", response_model=list[ResourceOut])
def list_resources(user: dict = Depends(get_current_user)) -> list[ResourceOut]:
    return [_resource_out(r) for r in acl.visible_resources(user)]


@router.get("/resources/{resource_id}/nodes")
def list_resource_nodes(resource_id: int, user: dict = Depends(require_admin)) -> dict:
    return {"resource_id": resource_id, "node_ids": acl.list_resource_node_ids(actor=user, resource_id=resource_id)}


@router.put("/resources/{resource_id}/nodes")
def update_resource_nodes(resource_id: int, payload: dict, user: dict = Depends(require_admin)) -> dict:
    node_ids_raw = payload.get("node_ids", [])
    if not isinstance(node_ids_raw, list):
        raise HTTPException(status_code=400, detail="node_ids must be a list")
    node_ids = [int(n) for n in node_ids_raw]
    updated = acl.set_resource_node_ids(actor=user, resource_id=resource_id, node_ids=node_ids)
    return {"resource_id": resource_id, "node_ids": updated}


@router.get("/me/permissions")
def my_permissions(user: dict = Depends(get_current_user)) -> dict:
    rows = acl.permissions.list_for_groups(acl.access._effective_group_ids(user["id"]))
    allowed = sorted({r["permission_code"] for r in rows if r["allow"] == 1})
    return {"permissions": allowed, "is_admin": user["role"] == "admin", "admin_level": user["admin_level"]}


@router.post("/permissions/grant", response_model=PermissionOut)
def grant_permission(payload: PermissionGrant, user: dict = Depends(require_admin)) -> PermissionOut:
    row = acl.grant_permission(
        actor=user,
        group_id=payload.group_id,
        resource_id=payload.resource_id,
        permission_code=payload.permission_code,
        allow=payload.allow,
    )
    return _perm_out(row)


@router.get("/permissions", response_model=list[PermissionOut])
def list_permissions(_: dict = Depends(require_admin)) -> list[PermissionOut]:
    return [_perm_out(r) for r in PermissionRepository().list_all()]


@router.delete("/permissions/{permission_id}")
def delete_permission(permission_id: int, user: dict = Depends(require_admin)) -> dict:
    acl.access.assert_permission(user, PERM_MANAGE_PERMISSIONS)
    deleted = PermissionRepository().delete(permission_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found")
    return {"status": "deleted"}


@router.get("/admin/management")
def management_data(user: dict = Depends(require_admin)) -> dict:
    acl.access.assert_permission(user, PERM_MANAGE_PERMISSIONS)
    users = UserRepository().list_users()
    groups = GroupRepository().list_groups()
    nodes = NodeRepository().list_nodes()
    resources = ResourceRepository().list_resources()
    resource_nodes = ResourceNodeRepository().list_all()
    permissions = PermissionRepository().list_all()
    bindings = []
    ugr = UserGroupRepository()
    for u in users:
        for gid in ugr.list_user_group_ids(u["id"]):
            bindings.append({"user_id": u["id"], "group_id": gid})
    return {
        "users": users,
        "groups": groups,
        "nodes": nodes,
        "resources": resources,
        "resource_nodes": resource_nodes,
        "permissions": permissions,
        "user_groups": bindings,
    }
