import json
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, status

from .connectors import connector_for
from .config import AGENT_HEARTBEAT_TTL_SEC, TEMP_DIR
from .repositories import (
    AgentJobRepository,
    FileRepository,
    GroupRepository,
    NodeRepository,
    PermissionRepository,
    ResourceFolderRepository,
    ResourceNodeRepository,
    ResourceRepository,
    ServiceSettingsRepository,
    TransferBlobRepository,
    UserGroupRepository,
    UserRepository,
    VolumeRepository,
)
from .security import create_access_token, hash_password, verify_password

PERM_VIEW = "view"
PERM_READ = "read"
PERM_WRITE = "write"
PERM_DELETE = "delete"
PERM_MANAGE_USERS = "manage_users"
PERM_MANAGE_GROUPS = "manage_groups"
PERM_MANAGE_NODES = "manage_nodes"
PERM_MANAGE_VOLUMES = "manage_volumes"
PERM_MANAGE_PERMISSIONS = "manage_permissions"
PERM_ADMIN_PANEL = "admin_panel"
SETTINGS_USER_ARCHIVE = "user_archive_on_delete"


class AccessService:
    def __init__(self) -> None:
        self.groups = GroupRepository()
        self.user_groups = UserGroupRepository()
        self.permissions = PermissionRepository()

    def _effective_group_ids(self, user_id: int) -> list[int]:
        direct = self.user_groups.list_user_group_ids(user_id)
        result: set[int] = set()
        for g in direct:
            result.update(self.groups.ancestor_ids(g))
        return list(result)

    def has_permission(self, user: dict, permission_code: str, resource_id: int | None = None) -> bool:
        if user["admin_level"] == "super_admin":
            return True
        gids = self._effective_group_ids(user["id"])
        rows = self.permissions.list_for_groups(gids)
        allow = False
        for row in rows:
            matches_resource = row["resource_id"] is None or row["resource_id"] == resource_id
            if row["permission_code"] == permission_code and matches_resource:
                if row["allow"] == 0:
                    return False
                allow = True
        return allow

    def assert_permission(self, user: dict, permission_code: str, resource_id: int | None = None) -> None:
        if not self.has_permission(user, permission_code, resource_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Permission denied: {permission_code}")

    def can_manage_group(self, user: dict, group_id: int) -> bool:
        if user["admin_level"] == "super_admin":
            return True
        scope_id = user.get("admin_scope_group_id")
        if user["admin_level"] in ("org_admin", "group_admin") and scope_id:
            descendants = self.groups.descendant_ids(scope_id)
            return group_id in descendants
        return False


class AuthService:
    def __init__(self) -> None:
        self.users = UserRepository()
        self.resources = ResourceRepository()
        self.groups = GroupRepository()
        self.user_groups = UserGroupRepository()
        self.permissions = PermissionRepository()

    def register_user(self, actor: dict, username: str, password: str, role: str, admin_level: str, admin_scope_group_id: int | None) -> dict:
        if self.users.get_by_username(username):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
        if role == "admin" and actor["admin_level"] != "super_admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only super_admin can create admins")
        if role != "admin":
            admin_level = "none"
            admin_scope_group_id = None
        user = self.users.create(
            username=username,
            password_hash=hash_password(password),
            role=role,
            admin_level=admin_level,
            admin_scope_group_id=admin_scope_group_id,
        )
        self._provision_personal_resource(user)
        return user

    def _provision_personal_resource(self, user: dict) -> None:
        existing_resources = self.resources.list_resources()
        personal_code = f"user.{user['id']}.personal"
        if any(r["code"] == personal_code for r in existing_resources):
            return
        root = next((r for r in existing_resources if r["path"] == "/"), None)
        resource = self.resources.create(
            {
                "name": f"Личное облако {user['username']}",
                "code": personal_code,
                "path": f"/users/{user['username']}",
                "resource_type": "folder",
                "size_limit_mb": 0,
                "parent_id": root["id"] if root else None,
                "is_hidden": False,
            }
        )
        group = self.groups.create(
            name=f"Группа {user['username']}",
            code=f"user.{user['id']}.group",
            group_type="personal",
            parent_id=None,
        )
        self.user_groups.bind(user_id=user["id"], group_id=group["id"])
        for code in ("view", "read", "write", "delete"):
            self.permissions.grant(group["id"], resource["id"], code, True)

    def login(self, username: str, password: str) -> str:
        user = self.users.get_by_username(username)
        if not user or bool(user.get("is_blocked")):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="нет такого пользователя")
        if not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return create_access_token(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
            admin_level=user["admin_level"],
        )


class ACLService:
    def __init__(self) -> None:
        self.access = AccessService()
        self.groups = GroupRepository()
        self.user_groups = UserGroupRepository()
        self.resources = ResourceRepository()
        self.folders = ResourceFolderRepository()
        self.resource_nodes = ResourceNodeRepository()
        self.permissions = PermissionRepository()
        self.users = UserRepository()

    def create_group(self, actor: dict, name: str, code: str, group_type: str, parent_id: int | None) -> dict:
        self.access.assert_permission(actor, PERM_MANAGE_GROUPS)
        if actor["admin_level"] != "super_admin" and not parent_id:
            raise HTTPException(status_code=403, detail="Non-super admin must create groups inside own scope")
        if parent_id and not self.access.can_manage_group(actor, parent_id):
            raise HTTPException(status_code=403, detail="Out of admin scope")
        return self.groups.create(name=name, code=code, group_type=group_type, parent_id=parent_id)

    def delete_group(self, actor: dict, group_id: int) -> bool:
        self.access.assert_permission(actor, PERM_MANAGE_GROUPS)
        if not self.groups.get_by_id(group_id):
            raise HTTPException(status_code=404, detail="Group not found")
        if not self.access.can_manage_group(actor, group_id):
            raise HTTPException(status_code=403, detail="Out of admin scope")
        members_count = self.user_groups.count_users_in_group(group_id)
        if members_count > 0:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete group: it still has {members_count} user(s). Remove members first.",
            )
        return self.groups.delete(group_id)

    def bind_user_group(self, actor: dict, user_id: int, group_id: int) -> None:
        self.access.assert_permission(actor, PERM_MANAGE_USERS)
        if not self.access.can_manage_group(actor, group_id):
            raise HTTPException(status_code=403, detail="Out of admin scope")
        if not self.users.get_by_id(user_id):
            raise HTTPException(status_code=404, detail="User not found")
        self.user_groups.bind(user_id=user_id, group_id=group_id)

    def create_resource(self, actor: dict, payload: dict) -> dict:
        self.access.assert_permission(actor, PERM_MANAGE_PERMISSIONS)
        return self.resources.create(payload)

    def update_resource(self, actor: dict, resource_id: int, payload: dict) -> dict:
        self.access.assert_permission(actor, PERM_MANAGE_PERMISSIONS)
        updated = self.resources.update(resource_id=resource_id, data=payload)
        if not updated:
            raise HTTPException(status_code=404, detail="Resource not found")
        return updated

    def grant_permission(self, actor: dict, group_id: int, resource_id: int | None, permission_code: str, allow: bool) -> dict:
        self.access.assert_permission(actor, PERM_MANAGE_PERMISSIONS)
        if not self.access.can_manage_group(actor, group_id):
            raise HTTPException(status_code=403, detail="Out of admin scope")
        return self.permissions.grant(group_id=group_id, resource_id=resource_id, permission_code=permission_code, allow=allow)

    def visible_resources(self, user: dict) -> list[dict]:
        resources = self.resources.list_resources()
        if user["admin_level"] == "super_admin":
            return resources
        return [r for r in resources if self.access.has_permission(user, PERM_VIEW, r["id"])]

    @staticmethod
    def normalize_folder_path(folder_path: str) -> str:
        p = (folder_path or "").strip()
        if not p:
            raise HTTPException(status_code=400, detail="Folder path is required")
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p[:-1]
        return p

    def create_folder(self, actor: dict, resource_id: int, folder_path: str) -> dict:
        self.access.assert_permission(actor, PERM_WRITE, resource_id=resource_id)
        if not self.resources.get_by_id(resource_id):
            raise HTTPException(status_code=404, detail="Resource not found")
        normalized = self.normalize_folder_path(folder_path)
        return self.folders.create(resource_id=resource_id, folder_path=normalized, created_by=actor["id"])

    def list_folders(self, actor: dict, resource_id: int) -> list[dict]:
        self.access.assert_permission(actor, PERM_VIEW, resource_id=resource_id)
        return self.folders.list_by_resource(resource_id=resource_id)

    def list_resource_node_ids(self, actor: dict, resource_id: int) -> list[int]:
        self.access.assert_permission(actor, PERM_MANAGE_PERMISSIONS)
        if not self.resources.get_by_id(resource_id):
            raise HTTPException(status_code=404, detail="Resource not found")
        return self.resource_nodes.list_node_ids(resource_id)

    def set_resource_node_ids(self, actor: dict, resource_id: int, node_ids: list[int]) -> list[int]:
        self.access.assert_permission(actor, PERM_MANAGE_PERMISSIONS)
        if not self.resources.get_by_id(resource_id):
            raise HTTPException(status_code=404, detail="Resource not found")
        existing_nodes = {int(n["id"]) for n in NodeRepository().list_nodes()}
        invalid = [nid for nid in node_ids if int(nid) not in existing_nodes]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Unknown node ids: {invalid}")
        self.resource_nodes.set_nodes(resource_id=resource_id, node_ids=node_ids)
        return self.resource_nodes.list_node_ids(resource_id)


class ServiceSettingsService:
    def __init__(self) -> None:
        self.repo = ServiceSettingsRepository()
        self.resources = ResourceRepository()

    @staticmethod
    def _normalize_folder_path(folder_path: str | None) -> str:
        p = (folder_path or "/").strip() or "/"
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p[:-1]
        return p

    def get_user_archive_settings(self) -> dict:
        raw = self.repo.get(SETTINGS_USER_ARCHIVE)
        base = {
            "enabled": False,
            "resource_id": None,
            "folder_path": "/archives",
            "download_timeout_sec": 120,
        }
        if not raw:
            return base
        val = raw.get("value", {})
        merged = {
            "enabled": bool(val.get("enabled", False)),
            "resource_id": int(val["resource_id"]) if val.get("resource_id") is not None else None,
            "folder_path": self._normalize_folder_path(val.get("folder_path")),
            "download_timeout_sec": max(15, min(1800, int(val.get("download_timeout_sec", 120)))),
        }
        if merged["resource_id"] is not None and not self.resources.get_by_id(merged["resource_id"]):
            merged["resource_id"] = None
        return merged

    def save_user_archive_settings(self, payload: dict) -> dict:
        settings = {
            "enabled": bool(payload.get("enabled", False)),
            "resource_id": int(payload["resource_id"]) if payload.get("resource_id") not in (None, "") else None,
            "folder_path": self._normalize_folder_path(payload.get("folder_path")),
            "download_timeout_sec": max(15, min(1800, int(payload.get("download_timeout_sec", 120)))),
        }
        if settings["resource_id"] is not None and not self.resources.get_by_id(settings["resource_id"]):
            raise HTTPException(status_code=404, detail="Archive target resource not found")
        self.repo.set(SETTINGS_USER_ARCHIVE, settings)
        return settings


class UserLifecycleService:
    def __init__(self) -> None:
        self.users = UserRepository()
        self.resources = ResourceRepository()
        self.files = FileRepository()
        self.volumes = VolumeRepository()
        self.nodes = NodeRepository()
        self.jobs = AgentJobRepository()
        self.blobs = TransferBlobRepository()
        self.file_service = FileService()
        self.settings = ServiceSettingsService()

    @staticmethod
    def _join_path(folder_path: str, file_name: str) -> str:
        folder = folder_path if folder_path.startswith("/") else "/" + folder_path
        if folder == "/":
            return f"/{file_name}"
        return f"{folder.rstrip('/')}/{file_name}"

    @staticmethod
    def _archive_name(user: dict) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"user_{user['username']}_{user['id']}_{stamp}.zip"

    def _fetch_blob_for_file(self, file_row: dict, timeout_sec: int) -> dict | None:
        file_id = int(file_row["id"])
        blob = self.blobs.latest_ready_for_file(file_id, "from_agent")
        if blob and Path(blob["local_path"]).exists():
            return blob

        if not file_row.get("storage_rel_path"):
            return None
        node = self.nodes.get_by_id(file_row["node_id"])
        volume = self.volumes.get_by_id(file_row["volume_id"])
        if not node or node.get("connection_type") != "agent" or not volume:
            return None

        self.jobs.create(
            node_id=file_row["node_id"],
            job_type="collect_file",
            payload={
                "file_id": file_id,
                "storage_rel_path": file_row["storage_rel_path"],
                "file_name": file_row["file_name"],
                "volume_mount_path": volume["mount_path"],
            },
        )
        deadline = time.time() + max(5, int(timeout_sec))
        while time.time() < deadline:
            blob = self.blobs.latest_ready_for_file(file_id, "from_agent")
            if blob and Path(blob["local_path"]).exists():
                return blob
            time.sleep(1)
        return None

    def _build_personal_archive(self, user: dict, personal_resource: dict, timeout_sec: int) -> tuple[Path, dict]:
        Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)
        archive_path = Path(TEMP_DIR) / self._archive_name(user)
        rows = self.files.list_by_resource(int(personal_resource["id"]))
        report = {"resource_id": personal_resource["id"], "files_total": len(rows), "files_archived": 0, "files_missed": []}

        with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as zf:
            for row in rows:
                arcname = str(row.get("logical_path") or f"/{row['file_name']}").lstrip("/") or row["file_name"]
                blob = self._fetch_blob_for_file(row, timeout_sec=timeout_sec)
                if not blob:
                    report["files_missed"].append({"file_id": row["id"], "path": row.get("logical_path"), "reason": "blob_unavailable"})
                    continue
                local_path = Path(blob["local_path"])
                if not local_path.exists():
                    report["files_missed"].append({"file_id": row["id"], "path": row.get("logical_path"), "reason": "blob_missing_on_disk"})
                    continue
                zf.write(local_path, arcname=arcname)
                report["files_archived"] += 1
                self.blobs.consume(int(blob["id"]))
                try:
                    local_path.unlink(missing_ok=True)
                except Exception:
                    pass

            manifest = {
                "user_id": user["id"],
                "username": user["username"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report": report,
            }
            zf.writestr("_archive_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        return archive_path, report

    def _upload_archive(self, actor: dict, archive_path: Path, settings: dict) -> dict:
        if not settings.get("resource_id"):
            raise HTTPException(status_code=400, detail="Archive target resource is not configured")
        size_bytes = archive_path.stat().st_size
        file_name = archive_path.name
        logical_path = self._join_path(settings["folder_path"], file_name)
        return self.file_service.create_uploaded_file(
            user=actor,
            resource_id=int(settings["resource_id"]),
            logical_path=logical_path,
            file_name=file_name,
            temp_path=archive_path,
            size_bytes=size_bytes,
        )

    def _personal_resource(self, user: dict) -> dict | None:
        code = f"user.{user['id']}.personal"
        return next((r for r in self.resources.list_resources() if r["code"] == code), None)

    def delete_user(self, actor: dict, user_id: int) -> dict:
        user = self.users.get_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        settings = self.settings.get_user_archive_settings()
        personal_resource = self._personal_resource(user)
        archive_result = {"attempted": False, "uploaded": False, "file_id": None, "report": None, "error": None}

        if settings.get("enabled") and not settings.get("resource_id"):
            raise HTTPException(status_code=400, detail="Archive is enabled but destination resource is not configured")

        if settings.get("enabled") and personal_resource:
            archive_result["attempted"] = True
            try:
                if int(settings.get("resource_id") or 0) == int(personal_resource["id"]):
                    raise HTTPException(status_code=400, detail="Archive destination cannot be user's personal resource")
                archive_path, report = self._build_personal_archive(
                    user=user,
                    personal_resource=personal_resource,
                    timeout_sec=int(settings.get("download_timeout_sec", 120)),
                )
                if report.get("files_missed"):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Archive is incomplete, missed files: {len(report.get('files_missed', []))}",
                    )
                uploaded = self._upload_archive(actor=actor, archive_path=archive_path, settings=settings)
                archive_result["uploaded"] = True
                archive_result["file_id"] = uploaded["id"]
                archive_result["report"] = report
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Cannot archive user personal space: {exc}") from exc

        owned_files = self.files.list_by_owner(user_id)
        for f in owned_files:
            self.file_service.delete_file(int(f["id"]))

        if personal_resource:
            resource_files = self.files.list_by_resource(int(personal_resource["id"]))
            for f in resource_files:
                if int(f["owner_id"]) == int(user_id):
                    continue
                self.file_service.delete_file(int(f["id"]))

        if personal_resource:
            try:
                deleted_resource = self.resources.delete(int(personal_resource["id"]))
            except Exception as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot delete user's personal resource after archiving: {exc}",
                ) from exc
            if not deleted_resource:
                raise HTTPException(status_code=400, detail="Cannot delete user's personal resource after archiving")

        deleted = self.users.delete(user_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="User not found")
        return {"status": "deleted", "archive": archive_result}


class NodeService:
    def __init__(self) -> None:
        self.nodes = NodeRepository()

    def check_connection(self, node_id: int) -> tuple[bool, str]:
        node = self.nodes.get_by_id(node_id)
        if not node:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
        if node["connection_type"] == "agent":
            if not node.get("last_seen"):
                return False, "No heartbeat yet from agent"
            last_seen = datetime.fromisoformat(node["last_seen"])
            delta = (datetime.now(timezone.utc) - last_seen).total_seconds()
            if delta <= AGENT_HEARTBEAT_TTL_SEC:
                return True, f"Agent online, last heartbeat {int(delta)} sec ago"
            return False, f"Agent offline, last heartbeat {int(delta)} sec ago"
        connector = connector_for(node)
        ok, message = connector.check(node)
        if ok:
            self.nodes.set_last_seen(node_id)
        return ok, message


class AdminDashboardService:
    def __init__(self) -> None:
        self.nodes = NodeRepository()
        self.volumes = VolumeRepository()

    @staticmethod
    def _mount_key(os_type: str, mount_path: str) -> str:
        if os_type == "windows":
            return (mount_path[:2].upper() if len(mount_path) >= 2 else mount_path.upper())
        return mount_path

    @staticmethod
    def _linux_best_disk_mount(mount_path: str, disks: list[dict]) -> str:
        path = mount_path if mount_path.startswith("/") else "/" + mount_path
        candidates = [d["mount"] for d in disks if path.startswith(d["mount"])]
        if not candidates:
            return "/"
        return max(candidates, key=len)

    def node_detail(self, node_id: int) -> dict:
        node = self.nodes.get_by_id(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        if node["connection_type"] == "agent":
            os_type = node.get("os_type") or "linux"
            try:
                disks = json.loads(node.get("disks_json") or "[]")
            except json.JSONDecodeError:
                disks = []
        else:
            connector = connector_for(node)
            info = connector.system_info(node)
            if not info.get("ok"):
                raise HTTPException(status_code=400, detail=f"Cannot inspect node: {info.get('message')}")
            os_type = info.get("os_type", "linux")
            disks = info.get("disks", [])
        node_volumes = self.volumes.list_volumes(node_id=node_id)

        by_disk_quota: dict[str, int] = {}
        for v in node_volumes:
            if os_type == "linux":
                mk = self._linux_best_disk_mount(v["mount_path"], disks)
            else:
                mk = self._mount_key(os_type, v["mount_path"])
            quota_bytes = int(v.get("quota_bytes") or 0)
            if quota_bytes <= 0:
                quota_bytes = int(v.get("quota_gb", 0)) * 1024 * 1024 * 1024
            by_disk_quota[mk] = by_disk_quota.get(mk, 0) + quota_bytes

        available_places = []
        for d in disks:
            mk = self._mount_key(os_type, d["mount"])
            allocated_bytes = by_disk_quota.get(mk, 0)
            allocated_gb = round(allocated_bytes / (1024**3), 3)
            available_places.append(
                {
                    "name": d["name"],
                    "mount": d["mount"],
                    "total_gb": d["total_gb"],
                    "free_gb_raw": d["free_gb"],
                    "allocated_gb_for_volumes": allocated_gb,
                    "free_gb_for_new_volumes": max(0, round(float(d["free_gb"]) - allocated_gb, 3)),
                }
            )

        return {
            "node": node,
            "os_type": os_type,
            "volumes": node_volumes,
            "available_places": available_places,
        }

    def dashboard(self) -> dict:
        nodes = self.nodes.list_nodes()
        volumes = self.volumes.list_volumes()
        now = datetime.now(timezone.utc)
        active_count = 0
        for n in nodes:
            online = bool(n["is_active"])
            if n.get("connection_type") == "agent":
                last_seen_raw = n.get("last_seen")
                if not last_seen_raw:
                    online = False
                else:
                    try:
                        delta = (now - datetime.fromisoformat(last_seen_raw)).total_seconds()
                        online = online and (delta <= AGENT_HEARTBEAT_TTL_SEC)
                    except Exception:
                        online = False
            n["is_online"] = online
            # Keep UI behavior consistent: status badges and charts should reflect real online state.
            n["is_active"] = online
            if online:
                active_count += 1
        total_quota_bytes = 0
        for v in volumes:
            qb = int(v.get("quota_bytes") or 0)
            if qb <= 0:
                qb = int(v.get("quota_gb", 0)) * 1024 * 1024 * 1024
            total_quota_bytes += qb
        total_quota = round(total_quota_bytes / (1024**3), 3)
        total_used_bytes = sum(int(v.get("used_bytes", 0)) for v in volumes)
        total_used = round(total_used_bytes / (1024**3), 3)
        return {
            "nodes_total": len(nodes),
            "nodes_active": active_count,
            "total_quota_gb": total_quota,
            "total_used_gb": total_used,
            "total_free_gb": max(0, total_quota - total_used),
            "nodes": nodes,
            "volumes_total": len(volumes),
        }


class ProvisioningService:
    def __init__(self) -> None:
        self.nodes = NodeRepository()
        self.volumes = VolumeRepository()
        self.jobs = AgentJobRepository()

    def provision_volume(self, node_id: int, mount_path: str, quota_bytes: int, label: str) -> dict:
        node = self.nodes.get_by_id(node_id)
        if not node:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
        if not node["is_active"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Node is inactive")
        qb = max(1, int(quota_bytes))
        qg = max(1, qb // (1024 * 1024 * 1024) + (1 if qb % (1024 * 1024 * 1024) else 0))
        if node["connection_type"] == "agent":
            volume = self.volumes.create(node_id=node_id, mount_path=mount_path, label=label, quota_bytes=qb)
            self.jobs.create(
                node_id=node_id,
                job_type="provision_volume",
                payload={"volume_id": volume["id"], "mount_path": mount_path, "quota_gb": qg, "quota_bytes": qb, "label": label},
            )
            return volume
        connector = connector_for(node)
        ok, message = connector.provision_volume(node, mount_path, qg, label)
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Provisioning failed: {message}")
        return self.volumes.create(node_id=node_id, mount_path=mount_path, label=label, quota_bytes=qb)


class PlacementService:
    def __init__(self) -> None:
        self.volumes = VolumeRepository()
        self.nodes = NodeRepository()
        self.files = FileRepository()

    def choose_volume(self, *, size_mb: int, required_bytes: int | None = None, allowed_node_ids: list[int] | None = None) -> dict:
        requested_bytes = int(required_bytes) if required_bytes is not None else int(size_mb) * 1024 * 1024
        if requested_bytes <= 0:
            requested_bytes = 1
        explicit_allowed = {int(n) for n in (allowed_node_ids or []) if int(n) > 0}
        effective_allowed = set(explicit_allowed)
        if not effective_allowed:
            all_nodes = self.nodes.list_nodes()
            preferred = {int(n["id"]) for n in all_nodes if bool(n.get("store_all_data", 0))}
            if preferred:
                effective_allowed = preferred
        candidates = []
        now = datetime.now(timezone.utc)
        all_volumes = self.volumes.list_volumes()
        file_used_bytes_by_volume = self.files.used_size_bytes_by_volumes([int(v["id"]) for v in all_volumes])
        for v in all_volumes:
            if not v["is_active"]:
                continue
            if effective_allowed and int(v["node_id"]) not in effective_allowed:
                continue
            node = self.nodes.get_by_id(v["node_id"])
            if not node or not node["is_active"]:
                continue
            if node["connection_type"] == "agent":
                last_seen_raw = node.get("last_seen")
                if not last_seen_raw:
                    continue
                try:
                    delta = (now - datetime.fromisoformat(last_seen_raw)).total_seconds()
                except Exception:
                    continue
                if delta > AGENT_HEARTBEAT_TTL_SEC:
                    continue
            quota_bytes = int(v.get("quota_bytes") or 0)
            if quota_bytes <= 0:
                quota_bytes = int(v.get("quota_gb", 0)) * 1024 * 1024 * 1024
            used_bytes = int(v.get("used_bytes", 0))
            files_used_bytes = int(file_used_bytes_by_volume.get(int(v["id"]), 0))
            effective_used_bytes = max(used_bytes, files_used_bytes)
            free_bytes = max(0, quota_bytes - effective_used_bytes)
            candidate = dict(v)
            candidate["_free_bytes"] = free_bytes
            candidate["_storage_priority"] = int(node.get("storage_priority", 0))
            candidates.append(candidate)
        candidates.sort(key=lambda v: (v.get("_storage_priority", 0), v.get("_free_bytes", 0)), reverse=True)
        for volume in candidates:
            if int(volume.get("_free_bytes", 0)) >= requested_bytes:
                return volume
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active volume with enough free space")


class FileService:
    def __init__(self) -> None:
        self.files = FileRepository()
        self.volumes = VolumeRepository()
        self.placement = PlacementService()
        self.access = AccessService()
        self.nodes = NodeRepository()
        self.jobs = AgentJobRepository()
        self.blobs = TransferBlobRepository()
        self.resources = ResourceRepository()
        self.resource_nodes = ResourceNodeRepository()
        self.users = UserRepository()

    def _check_resource_quota(self, resource_id: int, add_size_mb: int) -> None:
        resource = self.resources.get_by_id(resource_id)
        if not resource:
            raise HTTPException(status_code=404, detail="Resource not found")
        size_limit_mb = int(resource.get("size_limit_mb", 0) or 0)
        if size_limit_mb <= 0:
            return
        used_mb = self.files.used_size_mb_by_resource(resource_id)
        if used_mb + int(add_size_mb) > size_limit_mb:
            raise HTTPException(
                status_code=400,
                detail=f"Resource size limit exceeded: {used_mb + int(add_size_mb)} MB > {size_limit_mb} MB",
            )

    def create_file(self, user: dict, file_name: str, logical_path: str, size_mb: int, resource_id: int) -> dict:
        self.access.assert_permission(user, PERM_WRITE, resource_id=resource_id)
        self._check_resource_quota(resource_id=resource_id, add_size_mb=size_mb)
        allowed_nodes = self.resource_nodes.list_node_ids(resource_id)
        volume = self.placement.choose_volume(
            size_mb=size_mb,
            required_bytes=int(size_mb) * 1024 * 1024,
            allowed_node_ids=allowed_nodes,
        )
        node = self.nodes.get_by_id(volume["node_id"])
        file_row = self.files.create(
            {
                "file_name": file_name,
                "logical_path": logical_path,
                "size_mb": size_mb,
                "owner_id": user["id"],
                "node_id": volume["node_id"],
                "volume_id": volume["id"],
                "resource_id": resource_id,
                "status": "active",
            }
        )
        if node and node["connection_type"] != "agent":
            self.volumes.increment_used_space(volume_id=volume["id"], size_mb=size_mb)
        return file_row

    def create_uploaded_file(self, user: dict, resource_id: int, logical_path: str, file_name: str, temp_path: Path, size_bytes: int) -> dict:
        size_mb = max(1, size_bytes // (1024 * 1024) + (1 if size_bytes % (1024 * 1024) else 0))
        self.access.assert_permission(user, PERM_WRITE, resource_id=resource_id)
        self._check_resource_quota(resource_id=resource_id, add_size_mb=size_mb)
        allowed_nodes = self.resource_nodes.list_node_ids(resource_id)
        volume = self.placement.choose_volume(size_mb=size_mb, required_bytes=size_bytes, allowed_node_ids=allowed_nodes)
        node = self.nodes.get_by_id(volume["node_id"])
        if not node or node["connection_type"] != "agent":
            raise HTTPException(status_code=400, detail="File upload is supported only for agent nodes in this version")

        row = self.files.create(
            {
                "file_name": file_name,
                "logical_path": logical_path,
                "size_mb": size_mb,
                "owner_id": user["id"],
                "node_id": volume["node_id"],
                "volume_id": volume["id"],
                "resource_id": resource_id,
                "status": "pending_upload",
            }
        )
        storage_rel = f"resource_{resource_id}/file_{row['id']}_{file_name}"
        row = self.files.update(row["id"], {"storage_rel_path": storage_rel})
        Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)
        blob = self.blobs.create(
            file_id=row["id"],
            direction="to_agent",
            node_id=volume["node_id"],
            local_path=str(temp_path),
            size_bytes=size_bytes,
        )
        self.jobs.create(
            node_id=volume["node_id"],
            job_type="store_file",
            payload={
                "file_id": row["id"],
                "blob_id": blob["id"],
                "storage_rel_path": storage_rel,
                "volume_mount_path": volume["mount_path"],
                "file_meta": {
                    "file_id": row["id"],
                    "resource_id": row["resource_id"],
                    "owner_id": row["owner_id"],
                    "file_name": row["file_name"],
                    "logical_path": row["logical_path"],
                    "size_mb": row["size_mb"],
                    "size_bytes": size_bytes,
                },
            },
        )
        return row

    def sync_from_agent_volume_meta(self, node_id: int, volumes_meta: list[dict]) -> dict:
        stats = {"processed": 0, "upserted": 0, "skipped": 0}
        if not volumes_meta:
            return stats
        fallback_owner = self.users.get_by_username("admin") or self.users.get_by_id(1)
        resources_all = self.resources.list_resources()
        fallback_resource = next((r for r in resources_all if r.get("path") == "/"), resources_all[0] if resources_all else None)

        for vm in volumes_meta:
            mount_path = str(vm.get("mount_path") or "").strip()
            if not mount_path:
                continue
            volume = self.volumes.get_by_node_mount(node_id=node_id, mount_path=mount_path)
            if not volume:
                continue
            files_meta = vm.get("files")
            if not isinstance(files_meta, list):
                continue
            for item in files_meta:
                stats["processed"] += 1
                if not isinstance(item, dict):
                    stats["skipped"] += 1
                    continue
                storage_rel = str(item.get("storage_rel_path") or "").strip().lstrip("/").replace("\\", "/")
                if not storage_rel:
                    stats["skipped"] += 1
                    continue
                owner_id = int(item.get("owner_id") or (fallback_owner["id"] if fallback_owner else 0))
                resource_id = int(item.get("resource_id") or (fallback_resource["id"] if fallback_resource else 0))
                if owner_id <= 0 or not self.users.get_by_id(owner_id):
                    if not fallback_owner:
                        stats["skipped"] += 1
                        continue
                    owner_id = int(fallback_owner["id"])
                if resource_id <= 0 or not self.resources.get_by_id(resource_id):
                    if not fallback_resource:
                        stats["skipped"] += 1
                        continue
                    resource_id = int(fallback_resource["id"])
                size_mb = int(item.get("size_mb") or 0)
                if size_mb <= 0:
                    size_bytes = int(item.get("size_bytes") or 0)
                    size_mb = max(1, size_bytes // (1024 * 1024) + (1 if size_bytes % (1024 * 1024) else 0))
                file_name = str(item.get("file_name") or Path(storage_rel).name or "recovered.bin")
                logical_path = str(item.get("logical_path") or f"/{file_name}")
                self.files.upsert_from_agent(
                    {
                        "file_name": file_name,
                        "logical_path": logical_path,
                        "size_mb": size_mb,
                        "owner_id": owner_id,
                        "node_id": int(node_id),
                        "volume_id": int(volume["id"]),
                        "resource_id": resource_id,
                        "storage_rel_path": storage_rel,
                        "status": "active",
                    }
                )
                stats["upserted"] += 1
        return stats

    def request_download_from_agent(self, user: dict, file_id: int, proxy_token: str | None = None) -> dict:
        row = self.files.get_by_id(file_id)
        if not row:
            raise HTTPException(status_code=404, detail="File not found")
        if not self.can_read_file(user, row):
            raise HTTPException(status_code=403, detail="Access denied")
        if not row.get("storage_rel_path"):
            raise HTTPException(status_code=400, detail="File is not stored on node yet")
        self.files.set_status(file_id, "pending_download")
        volume = self.volumes.get_by_id(row["volume_id"])
        if not volume:
            raise HTTPException(status_code=404, detail="Volume not found")
        job = self.jobs.create(
            node_id=row["node_id"],
            job_type="collect_file",
            payload={
                "file_id": file_id,
                "storage_rel_path": row["storage_rel_path"],
                "file_name": row["file_name"],
                "volume_mount_path": volume["mount_path"],
                "proxy_token": proxy_token,
            },
        )
        return {"job_id": job["id"], "file_id": file_id}

    def mark_job_result(self, job_id: int, ok: bool, result: dict) -> None:
        job = self.jobs.get_by_id(job_id)
        if not job:
            return
        self.jobs.complete(job_id, ok, result)
        try:
            payload = json.loads(job["payload_json"])
        except Exception:
            payload = {}
        file_id = payload.get("file_id")
        if not file_id:
            return
        if ok and job["job_type"] == "store_file":
            blob_id = payload.get("blob_id")
            if blob_id:
                blob = self.blobs.get_by_id(int(blob_id))
                if blob:
                    self.blobs.consume(int(blob_id))
                    try:
                        Path(blob["local_path"]).unlink(missing_ok=True)
                    except Exception:
                        pass
            self.files.set_status(file_id, "active")
        elif ok and job["job_type"] == "collect_file":
            self.files.set_status(file_id, "active")
        elif not ok:
            self.files.set_status(file_id, "error")

    def can_read_file(self, user: dict, file_row: dict) -> bool:
        if user["admin_level"] == "super_admin" or user["id"] == file_row["owner_id"]:
            return True
        return self.access.has_permission(user, PERM_READ, file_row["resource_id"])

    def can_write_file(self, user: dict, file_row: dict) -> bool:
        if user["admin_level"] == "super_admin" or user["id"] == file_row["owner_id"]:
            return True
        return self.access.has_permission(user, PERM_WRITE, file_row["resource_id"])

    def can_delete_file(self, user: dict, file_row: dict) -> bool:
        if user["admin_level"] == "super_admin":
            return True
        return self.access.has_permission(user, PERM_DELETE, file_row["resource_id"])

    def delete_file(self, file_id: int) -> bool:
        existing = self.files.get_by_id(file_id)
        if not existing:
            return False
        node = self.nodes.get_by_id(existing["node_id"])
        if node and node["connection_type"] == "agent" and existing.get("storage_rel_path"):
            volume = self.volumes.get_by_id(existing["volume_id"])
            if volume:
                self.jobs.create(
                    node_id=existing["node_id"],
                    job_type="delete_file",
                    payload={
                        "file_id": existing["id"],
                        "storage_rel_path": existing["storage_rel_path"],
                        "volume_mount_path": volume["mount_path"],
                    },
                )
        blob_rows = self.blobs.list_for_file(file_id)
        self.blobs.delete_for_file(file_id)
        for blob in blob_rows:
            try:
                Path(blob["local_path"]).unlink(missing_ok=True)
            except Exception:
                pass
        deleted = self.files.delete(file_id)
        if deleted:
            if node and node["connection_type"] != "agent":
                self.volumes.decrement_used_space(volume_id=existing["volume_id"], size_mb=existing["size_mb"])
        return deleted
