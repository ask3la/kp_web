from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..dependencies import get_current_user, require_admin
from ..models import LoginRequest, TokenResponse, UserCreate, UserOut, UserPasswordUpdate, UserUpdate
from ..request_meta import client_ip
from ..repositories import AuditLogRepository, GroupRepository, UserGroupRepository, UserRepository
from ..services import AccessService, AuthService, PERM_MANAGE_USERS, UserLifecycleService
from ..security import hash_password

router = APIRouter(prefix="/auth", tags=["auth"])
auth_service = AuthService()
access = AccessService()
groups = GroupRepository()
user_groups = UserGroupRepository()
audit = AuditLogRepository()
user_lifecycle = UserLifecycleService()


def _user_out(row: dict) -> UserOut:
    return UserOut(
        id=row["id"],
        username=row["username"],
        role=row["role"],
        admin_level=row["admin_level"],
        admin_scope_group_id=row["admin_scope_group_id"],
        is_blocked=bool(row.get("is_blocked", 0)),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request) -> TokenResponse:
    token = auth_service.login(username=payload.username, password=payload.password)
    user = UserRepository().get_by_username(payload.username)
    if user:
        audit.create(
            event_code="login",
            message="User logged in",
            user_id=user["id"],
            username=user["username"],
            ip_address=client_ip(request),
            meta={"role": user["role"]},
        )
    return TokenResponse(access_token=token)


@router.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, actor: dict = Depends(require_admin)) -> UserOut:
    access.assert_permission(actor, PERM_MANAGE_USERS)
    user = auth_service.register_user(
        actor=actor,
        username=payload.username,
        password=payload.password,
        role=payload.role,
        admin_level=payload.admin_level,
        admin_scope_group_id=payload.admin_scope_group_id,
    )
    return _user_out(user)


@router.get("/users", response_model=list[UserOut])
def list_users(actor: dict = Depends(require_admin)) -> list[UserOut]:
    rows = UserRepository().list_users()
    if actor["admin_level"] == "super_admin":
        return [_user_out(r) for r in rows]
    scope = actor.get("admin_scope_group_id")
    if not scope:
        return [_user_out(actor)]
    allowed = groups.descendant_ids(scope)
    visible = []
    for u in rows:
        u_group_ids = set(user_groups.list_user_group_ids(u["id"]))
        if u_group_ids.intersection(allowed):
            visible.append(u)
    return [_user_out(r) for r in visible]


@router.put("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, payload: UserUpdate, actor: dict = Depends(require_admin)) -> UserOut:
    access.assert_permission(actor, PERM_MANAGE_USERS)
    repo = UserRepository()
    existing = repo.get_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if payload.username != existing["username"] and repo.get_by_username(payload.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    if payload.role == "admin" and actor["admin_level"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only super_admin can assign admin role")
    admin_level = payload.admin_level if payload.role == "admin" else "none"
    admin_scope_group_id = payload.admin_scope_group_id if payload.role == "admin" else None
    updated = repo.update_user(
        user_id=user_id,
        username=payload.username,
        role=payload.role,
        admin_level=admin_level,
        admin_scope_group_id=admin_scope_group_id,
    )
    return _user_out(updated)


@router.post("/users/{user_id}/password")
def set_user_password(user_id: int, payload: UserPasswordUpdate, actor: dict = Depends(require_admin)) -> dict:
    access.assert_permission(actor, PERM_MANAGE_USERS)
    repo = UserRepository()
    if not repo.get_by_id(user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    repo.set_password_hash(user_id=user_id, password_hash=hash_password(payload.password))
    return {"status": "ok"}


@router.post("/users/{user_id}/block")
def block_user(user_id: int, actor: dict = Depends(require_admin)) -> dict:
    access.assert_permission(actor, PERM_MANAGE_USERS)
    if actor["id"] == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot block current user")
    repo = UserRepository()
    if not repo.get_by_id(user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    repo.set_blocked(user_id=user_id, blocked=True)
    return {"status": "ok"}


@router.post("/users/{user_id}/unblock")
def unblock_user(user_id: int, actor: dict = Depends(require_admin)) -> dict:
    access.assert_permission(actor, PERM_MANAGE_USERS)
    repo = UserRepository()
    if not repo.get_by_id(user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    repo.set_blocked(user_id=user_id, blocked=False)
    return {"status": "ok"}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, actor: dict = Depends(require_admin)) -> dict:
    access.assert_permission(actor, PERM_MANAGE_USERS)
    if actor["id"] == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete current user")
    target = UserRepository().get_by_id(user_id)
    result = user_lifecycle.delete_user(actor=actor, user_id=user_id)
    audit.create(
        event_code="user_delete",
        message=f"Deleted user {target['username'] if target else user_id}",
        user_id=actor["id"],
        username=actor["username"],
        ip_address=client_ip(request),
        meta={"target_user_id": user_id, "archive": result.get("archive", {})},
    )
    return result


@router.get("/me", response_model=UserOut)
def me(user: dict = Depends(get_current_user)) -> UserOut:
    return _user_out(user)
