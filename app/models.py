from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=64)
    role: str = Field(pattern="^(admin|employee|client)$")
    admin_level: str = Field(default="none", pattern="^(none|group_admin|org_admin|super_admin)$")
    admin_scope_group_id: int | None = None


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    admin_level: str
    admin_scope_group_id: int | None
    is_blocked: bool
    created_at: datetime


class UserUpdate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    role: str = Field(pattern="^(admin|employee|client)$")
    admin_level: str = Field(default="none", pattern="^(none|group_admin|org_admin|super_admin)$")
    admin_scope_group_id: int | None = None


class UserPasswordUpdate(BaseModel):
    password: str = Field(min_length=6, max_length=64)


class GroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    code: str = Field(min_length=2, max_length=80)
    group_type: str = Field(min_length=2, max_length=50)
    parent_id: int | None = None


class GroupOut(BaseModel):
    id: int
    name: str
    code: str
    group_type: str
    parent_id: int | None
    created_at: datetime


class UserGroupBind(BaseModel):
    user_id: int
    group_id: int


class ResourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    code: str = Field(min_length=2, max_length=80)
    path: str = Field(min_length=2, max_length=255)
    resource_type: str = Field(min_length=2, max_length=50)
    size_limit_mb: int = Field(default=0, ge=0)
    parent_id: int | None = None
    is_hidden: bool = False


class ResourceOut(BaseModel):
    id: int
    name: str
    code: str
    path: str
    resource_type: str
    size_limit_mb: int
    parent_id: int | None
    is_hidden: bool
    created_at: datetime


class ResourceUpdate(BaseModel):
    size_limit_mb: int = Field(ge=0)


class ResourceFolderCreate(BaseModel):
    resource_id: int
    folder_path: str = Field(min_length=1, max_length=255)


class ResourceFolderOut(BaseModel):
    id: int
    resource_id: int
    folder_path: str
    created_by: int
    created_at: datetime


class PermissionGrant(BaseModel):
    group_id: int
    resource_id: int | None = None
    permission_code: str = Field(
        pattern="^(view|read|write|delete|share|manage_users|manage_groups|manage_nodes|manage_volumes|manage_permissions|admin_panel)$"
    )
    allow: bool = True


class PermissionOut(BaseModel):
    id: int
    group_id: int
    resource_id: int | None
    permission_code: str
    allow: bool
    created_at: datetime


class NodeCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    host: str = Field(min_length=2, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    connection_type: str = Field(pattern="^(agent|ssh)$")
    agent_url: str | None = Field(default=None, max_length=255)
    ssh_username: str | None = Field(default=None, max_length=100)
    ssh_password: str | None = Field(default=None, max_length=200)
    ssh_key_path: str | None = Field(default=None, max_length=255)
    agent_public_key: str | None = None
    storage_priority: int = Field(default=0, ge=0, le=1000)
    store_all_data: bool = False


class NodeUpdate(BaseModel):
    host: str | None = Field(default=None, min_length=2, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    agent_url: str | None = Field(default=None, max_length=255)
    ssh_username: str | None = Field(default=None, max_length=100)
    ssh_password: str | None = Field(default=None, max_length=200)
    ssh_key_path: str | None = Field(default=None, max_length=255)
    agent_public_key: str | None = None
    storage_priority: int | None = Field(default=None, ge=0, le=1000)
    store_all_data: bool | None = None
    is_active: bool | None = None


class NodeOut(BaseModel):
    id: int
    name: str
    host: str
    port: int
    connection_type: str
    agent_url: str | None
    ssh_username: str | None
    ssh_key_path: str | None
    has_agent_public_key: bool
    storage_priority: int
    store_all_data: bool
    is_active: bool
    last_seen: datetime | None
    created_at: datetime


class VolumeCreate(BaseModel):
    node_id: int
    mount_path: str = Field(min_length=2, max_length=255)
    label: str = Field(min_length=2, max_length=100)
    quota_bytes: int = Field(gt=0)


class VolumeUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=2, max_length=100)
    quota_gb: int | None = Field(default=None, gt=0, le=100000)
    is_active: bool | None = None


class VolumeOut(BaseModel):
    id: int
    node_id: int
    mount_path: str
    label: str
    quota_gb: int
    quota_bytes: int
    used_gb: int
    used_bytes: int
    is_active: bool
    created_at: datetime


class FileCreate(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    logical_path: str = Field(min_length=1, max_length=255)
    resource_id: int
    size_mb: int = Field(gt=0)


class FileUpdate(BaseModel):
    file_name: str | None = Field(default=None, min_length=1, max_length=255)
    logical_path: str | None = Field(default=None, min_length=1, max_length=255)
    status: str | None = Field(default=None, pattern="^(active|archived|deleted)$")


class FileOut(BaseModel):
    id: int
    file_name: str
    logical_path: str
    size_mb: int
    owner_id: int
    node_id: int
    volume_id: int
    resource_id: int
    status: str
    created_at: datetime
    updated_at: datetime


class ConnectionCheckResult(BaseModel):
    node_id: int
    ok: bool
    message: str
