from fastapi import APIRouter, Depends

from ..dependencies import require_admin
from ..services import (
    AccessService,
    AdminDashboardService,
    PERM_ADMIN_PANEL,
    PERM_MANAGE_USERS,
    PERM_MANAGE_NODES,
    PERM_MANAGE_PERMISSIONS,
    PERM_MANAGE_VOLUMES,
    ServiceSettingsService,
)

router = APIRouter(prefix="/admin", tags=["admin"])
access = AccessService()
dash = AdminDashboardService()
settings_service = ServiceSettingsService()


@router.get("/dashboard")
def dashboard(user: dict = Depends(require_admin)) -> dict:
    access.assert_permission(user, PERM_ADMIN_PANEL)
    return dash.dashboard()


@router.get("/nodes/{node_id}/detail")
def node_detail(node_id: int, user: dict = Depends(require_admin)) -> dict:
    access.assert_permission(user, PERM_ADMIN_PANEL)
    return dash.node_detail(node_id=node_id)


@router.get("/capabilities")
def capabilities(user: dict = Depends(require_admin)) -> dict:
    return {
        "manage_nodes": access.has_permission(user, PERM_MANAGE_NODES),
        "manage_volumes": access.has_permission(user, PERM_MANAGE_VOLUMES),
        "manage_users": access.has_permission(user, PERM_MANAGE_USERS),
        "manage_permissions": access.has_permission(user, PERM_MANAGE_PERMISSIONS),
        "admin_panel": access.has_permission(user, PERM_ADMIN_PANEL),
    }


@router.get("/settings")
def get_settings(user: dict = Depends(require_admin)) -> dict:
    access.assert_permission(user, PERM_ADMIN_PANEL)
    return {"user_archive": settings_service.get_user_archive_settings()}


@router.put("/settings")
def update_settings(payload: dict, user: dict = Depends(require_admin)) -> dict:
    access.assert_permission(user, PERM_MANAGE_USERS)
    archive_payload = payload.get("user_archive", payload)
    return {"user_archive": settings_service.save_user_archive_settings(archive_payload)}
