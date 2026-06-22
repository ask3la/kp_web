from datetime import datetime, timezone
import json
import secrets
from typing import Any

from .db import get_conn


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UserRepository:
    def create(self, username: str, password_hash: str, role: str, admin_level: str, admin_scope_group_id: int | None) -> dict[str, Any]:
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO users (username, password_hash, role, admin_level, admin_scope_group_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, password_hash, role, admin_level, admin_scope_group_id, utc_now_iso()),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def get_by_username(self, username: str) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def get_by_id(self, user_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT id, username, role, admin_level, admin_scope_group_id, is_blocked, created_at FROM users ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]

    def update_admin_attrs(self, user_id: int, admin_level: str, admin_scope_group_id: int | None) -> None:
        with get_conn() as conn:
            conn.execute(
                "UPDATE users SET admin_level = ?, admin_scope_group_id = ? WHERE id = ?",
                (admin_level, admin_scope_group_id, user_id),
            )
            conn.commit()

    def update_user(self, user_id: int, username: str, role: str, admin_level: str, admin_scope_group_id: int | None) -> dict[str, Any] | None:
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE users
                SET username = ?, role = ?, admin_level = ?, admin_scope_group_id = ?
                WHERE id = ?
                """,
                (username, role, admin_level, admin_scope_group_id, user_id),
            )
            conn.commit()
        return self.get_by_id(user_id)

    def set_password_hash(self, user_id: int, password_hash: str) -> None:
        with get_conn() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
            conn.commit()

    def set_blocked(self, user_id: int, blocked: bool) -> None:
        with get_conn() as conn:
            conn.execute("UPDATE users SET is_blocked = ? WHERE id = ?", (1 if blocked else 0, user_id))
            conn.commit()

    def delete(self, user_id: int) -> bool:
        with get_conn() as conn:
            cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cur.rowcount > 0


class GroupRepository:
    def create(self, name: str, code: str, group_type: str, parent_id: int | None) -> dict[str, Any]:
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO groups_acl (name, code, group_type, parent_id, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, code, group_type, parent_id, utc_now_iso()),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def get_by_id(self, group_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM groups_acl WHERE id = ?", (group_id,)).fetchone()
            return dict(row) if row else None

    def list_groups(self) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM groups_acl ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def delete(self, group_id: int) -> bool:
        with get_conn() as conn:
            cur = conn.execute("DELETE FROM groups_acl WHERE id = ?", (group_id,))
            conn.commit()
            return cur.rowcount > 0

    def descendant_ids(self, group_id: int) -> set[int]:
        groups = self.list_groups()
        by_parent: dict[int | None, list[int]] = {}
        for g in groups:
            by_parent.setdefault(g["parent_id"], []).append(g["id"])

        result = set()
        stack = [group_id]
        while stack:
            current = stack.pop()
            if current in result:
                continue
            result.add(current)
            stack.extend(by_parent.get(current, []))
        return result

    def ancestor_ids(self, group_id: int) -> set[int]:
        groups = {g["id"]: g for g in self.list_groups()}
        result = set()
        current = group_id
        while current and current in groups and current not in result:
            result.add(current)
            current = groups[current]["parent_id"]
        return result


class UserGroupRepository:
    def bind(self, user_id: int, group_id: int) -> None:
        with get_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO user_groups (user_id, group_id, created_at) VALUES (?, ?, ?)",
                (user_id, group_id, utc_now_iso()),
            )
            conn.commit()

    def unbind(self, user_id: int, group_id: int) -> None:
        with get_conn() as conn:
            conn.execute("DELETE FROM user_groups WHERE user_id = ? AND group_id = ?", (user_id, group_id))
            conn.commit()

    def list_user_group_ids(self, user_id: int) -> list[int]:
        with get_conn() as conn:
            rows = conn.execute("SELECT group_id FROM user_groups WHERE user_id = ?", (user_id,)).fetchall()
            return [int(r["group_id"]) for r in rows]

    def count_users_in_group(self, group_id: int) -> int:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM user_groups WHERE group_id = ?",
                (group_id,),
            ).fetchone()
            return int(row["cnt"]) if row else 0


class ResourceRepository:
    def create(self, data: dict[str, Any]) -> dict[str, Any]:
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO resources (name, code, path, resource_type, size_limit_mb, parent_id, is_hidden, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["name"],
                    data["code"],
                    data["path"],
                    data["resource_type"],
                    int(data.get("size_limit_mb", 0)),
                    data.get("parent_id"),
                    int(data.get("is_hidden", 0)),
                    utc_now_iso(),
                ),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def get_by_id(self, resource_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM resources WHERE id = ?", (resource_id,)).fetchone()
            return dict(row) if row else None

    def list_resources(self) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM resources ORDER BY path").fetchall()
            return [dict(r) for r in rows]

    def update(self, resource_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_by_id(resource_id)
        if not existing:
            return None
        merged = {**existing, **data}
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE resources
                SET size_limit_mb = ?
                WHERE id = ?
                """,
                (int(merged["size_limit_mb"]), resource_id),
            )
            conn.commit()
        return self.get_by_id(resource_id)

    def delete(self, resource_id: int) -> bool:
        with get_conn() as conn:
            cur = conn.execute("DELETE FROM resources WHERE id = ?", (resource_id,))
            conn.commit()
            return cur.rowcount > 0


class ResourceFolderRepository:
    def create(self, resource_id: int, folder_path: str, created_by: int) -> dict[str, Any]:
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO resource_folders (resource_id, folder_path, created_by, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (resource_id, folder_path, created_by, utc_now_iso()),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def get_by_id(self, folder_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM resource_folders WHERE id = ?", (folder_id,)).fetchone()
            return dict(row) if row else None

    def list_by_resource(self, resource_id: int) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM resource_folders WHERE resource_id = ? ORDER BY folder_path",
                (resource_id,),
            ).fetchall()
            return [dict(r) for r in rows]


class ResourceNodeRepository:
    def list_node_ids(self, resource_id: int) -> list[int]:
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT node_id FROM resource_nodes WHERE resource_id = ? ORDER BY node_id",
                (resource_id,),
            ).fetchall()
            return [int(r["node_id"]) for r in rows]

    def list_all(self) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM resource_nodes ORDER BY resource_id, node_id").fetchall()
            return [dict(r) for r in rows]

    def set_nodes(self, resource_id: int, node_ids: list[int]) -> None:
        uniq_ids = sorted({int(n) for n in node_ids if int(n) > 0})
        with get_conn() as conn:
            conn.execute("DELETE FROM resource_nodes WHERE resource_id = ?", (resource_id,))
            if uniq_ids:
                conn.executemany(
                    "INSERT INTO resource_nodes (resource_id, node_id, created_at) VALUES (?, ?, ?)",
                    [(resource_id, nid, utc_now_iso()) for nid in uniq_ids],
                )
            conn.commit()


class PermissionRepository:
    def grant(self, group_id: int, resource_id: int | None, permission_code: str, allow: bool) -> dict[str, Any]:
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO group_permissions (group_id, resource_id, permission_code, allow, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(group_id, resource_id, permission_code)
                DO UPDATE SET allow=excluded.allow
                """,
                (group_id, resource_id, permission_code, int(allow), utc_now_iso()),
            )
            conn.commit()
            row = conn.execute(
                """
                SELECT * FROM group_permissions
                WHERE group_id = ? AND resource_id IS ? AND permission_code = ?
                """,
                (group_id, resource_id, permission_code),
            ).fetchone()
            return dict(row)

    def list_for_groups(self, group_ids: list[int]) -> list[dict[str, Any]]:
        if not group_ids:
            return []
        placeholders = ",".join("?" for _ in group_ids)
        with get_conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM group_permissions WHERE group_id IN ({placeholders})",
                tuple(group_ids),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_all(self) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM group_permissions ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def delete(self, permission_id: int) -> bool:
        with get_conn() as conn:
            cur = conn.execute("DELETE FROM group_permissions WHERE id = ?", (permission_id,))
            conn.commit()
            return cur.rowcount > 0


class NodeRepository:
    def create(self, data: dict[str, Any]) -> dict[str, Any]:
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO nodes
                (
                    name, host, port, connection_type, agent_url, ssh_username, ssh_password, ssh_key_path,
                    is_active, agent_public_key, agent_token, storage_priority, store_all_data, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    data["name"],
                    data["host"],
                    data.get("port", 22),
                    data["connection_type"],
                    data.get("agent_url"),
                    data.get("ssh_username"),
                    data.get("ssh_password"),
                    data.get("ssh_key_path"),
                    data.get("agent_public_key"),
                    data.get("agent_token"),
                    int(data.get("storage_priority", 0)),
                    int(bool(data.get("store_all_data", False))),
                    utc_now_iso(),
                ),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def list_nodes(self) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM nodes ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def get_by_id(self, node_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
            return dict(row) if row else None

    def get_by_name(self, name: str) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE name = ?", (name,)).fetchone()
            return dict(row) if row else None

    def update(self, node_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_by_id(node_id)
        if not existing:
            return None
        merged = {**existing, **data}
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE nodes
                SET host = ?, port = ?, agent_url = ?, ssh_username = ?, ssh_password = ?, ssh_key_path = ?, agent_public_key = ?, agent_token = ?, storage_priority = ?, store_all_data = ?, is_active = ?
                WHERE id = ?
                """,
                (
                    merged["host"],
                    merged["port"],
                    merged.get("agent_url"),
                    merged.get("ssh_username"),
                    merged.get("ssh_password"),
                    merged.get("ssh_key_path"),
                    merged.get("agent_public_key"),
                    merged.get("agent_token"),
                    int(merged.get("storage_priority", 0)),
                    int(bool(merged.get("store_all_data", False))),
                    int(merged["is_active"]),
                    node_id,
                ),
            )
            conn.commit()
        return self.get_by_id(node_id)

    def upsert_agent_node(self, name: str, host: str, port: int, agent_url: str, agent_public_key: str) -> dict[str, Any]:
        existing = self.get_by_name(name)
        payload = {
            "name": name,
            "host": host,
            "port": port,
            "connection_type": "agent",
            "agent_url": agent_url,
            "ssh_username": None,
            "ssh_password": None,
            "ssh_key_path": None,
            "agent_public_key": agent_public_key,
            "agent_token": existing["agent_token"] if existing and existing.get("agent_token") else secrets.token_urlsafe(32),
        }
        if existing:
            return self.update(existing["id"], payload)
        return self.create(payload)

    def set_last_seen(self, node_id: int) -> None:
        with get_conn() as conn:
            conn.execute("UPDATE nodes SET last_seen = ? WHERE id = ?", (utc_now_iso(), node_id))
            conn.commit()

    def get_by_agent_token(self, token: str) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE agent_token = ?", (token,)).fetchone()
            return dict(row) if row else None

    def set_heartbeat(self, node_id: int, os_type: str | None, disks: list[dict] | None) -> None:
        with get_conn() as conn:
            conn.execute(
                "UPDATE nodes SET last_seen = ?, os_type = ?, disks_json = ? WHERE id = ?",
                (utc_now_iso(), os_type, json.dumps(disks or [], ensure_ascii=False), node_id),
            )
            conn.commit()

    def delete(self, node_id: int) -> bool:
        with get_conn() as conn:
            cur = conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
            conn.commit()
            return cur.rowcount > 0


class VolumeRepository:
    @staticmethod
    def _norm_mount(path: str) -> str:
        return str(path or "").replace("\\", "/").rstrip("/").lower()

    def create(self, node_id: int, mount_path: str, label: str, quota_bytes: int) -> dict[str, Any]:
        qb = max(1, int(quota_bytes))
        qg = max(1, qb // (1024 * 1024 * 1024) + (1 if qb % (1024 * 1024 * 1024) else 0))
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO volumes (node_id, mount_path, label, quota_gb, quota_bytes, used_gb, used_bytes, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, 0, 0, 1, ?)
                """,
                (node_id, mount_path, label, qg, qb, utc_now_iso()),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def list_volumes(self, node_id: int | None = None) -> list[dict[str, Any]]:
        with get_conn() as conn:
            if node_id is None:
                rows = conn.execute("SELECT * FROM volumes ORDER BY id").fetchall()
            else:
                rows = conn.execute("SELECT * FROM volumes WHERE node_id = ? ORDER BY id", (node_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_by_id(self, volume_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM volumes WHERE id = ?", (volume_id,)).fetchone()
            return dict(row) if row else None

    def get_by_node_mount(self, node_id: int, mount_path: str) -> dict[str, Any] | None:
        needle = self._norm_mount(mount_path)
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM volumes WHERE node_id = ?", (node_id,)).fetchall()
            for row in rows:
                if self._norm_mount(str(row["mount_path"])) == needle:
                    return dict(row)
            return None

    def update(self, volume_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_by_id(volume_id)
        if not existing:
            return None
        merged = {**existing, **data}
        quota_gb = int(merged["quota_gb"])
        quota_bytes = int(merged.get("quota_bytes", 0) or 0)
        if quota_bytes <= 0:
            quota_bytes = quota_gb * 1024 * 1024 * 1024
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE volumes
                SET label = ?, quota_gb = ?, quota_bytes = ?, is_active = ?
                WHERE id = ?
                """,
                (merged["label"], quota_gb, quota_bytes, int(merged["is_active"]), volume_id),
            )
            conn.commit()
        return self.get_by_id(volume_id)

    def delete(self, volume_id: int) -> bool:
        with get_conn() as conn:
            cur = conn.execute("DELETE FROM volumes WHERE id = ?", (volume_id,))
            conn.commit()
            return cur.rowcount > 0

    def increment_used_space(self, volume_id: int, size_mb: int) -> None:
        delta_bytes = int(size_mb) * 1024 * 1024
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE volumes
                SET used_bytes = used_bytes + ?,
                    used_gb = CAST((used_bytes + ?) / (1024 * 1024 * 1024) AS INTEGER)
                WHERE id = ?
                """,
                (delta_bytes, delta_bytes, volume_id),
            )
            conn.commit()

    def decrement_used_space(self, volume_id: int, size_mb: int) -> None:
        delta_bytes = int(size_mb) * 1024 * 1024
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE volumes
                SET used_bytes = CASE WHEN used_bytes > ? THEN used_bytes - ? ELSE 0 END
                WHERE id = ?
                """,
                (delta_bytes, delta_bytes, volume_id),
            )
            conn.execute(
                "UPDATE volumes SET used_gb = CAST(used_bytes / (1024 * 1024 * 1024) AS INTEGER) WHERE id = ?",
                (volume_id,),
            )
            conn.commit()

    def sync_used_space_for_node(self, node_id: int, mounts_meta: list[dict[str, Any]]) -> None:
        if not mounts_meta:
            return
        meta_by_mount = {self._norm_mount(str(m.get("mount_path", ""))): m for m in mounts_meta}
        with get_conn() as conn:
            volumes = conn.execute("SELECT id, mount_path FROM volumes WHERE node_id = ?", (node_id,)).fetchall()
            for row in volumes:
                found = meta_by_mount.get(self._norm_mount(str(row["mount_path"])))
                if not found:
                    continue
                used_bytes = int(found.get("used_bytes", 0))
                used_gb = used_bytes // (1024 * 1024 * 1024)
                conn.execute(
                    "UPDATE volumes SET used_bytes = ?, used_gb = ? WHERE id = ?",
                    (max(0, used_bytes), max(0, used_gb), row["id"]),
                )
            conn.commit()


class FileRepository:
    def create(self, data: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO files
                (file_name, logical_path, size_mb, owner_id, node_id, volume_id, resource_id, storage_rel_path, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["file_name"],
                    data["logical_path"],
                    data["size_mb"],
                    data["owner_id"],
                    data["node_id"],
                    data["volume_id"],
                    data["resource_id"],
                    data.get("storage_rel_path"),
                    data.get("status", "active"),
                    now,
                    now,
                ),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def list_files(self) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM files ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def list_by_owner(self, owner_id: int) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM files WHERE owner_id = ? ORDER BY id", (owner_id,)).fetchall()
            return [dict(r) for r in rows]

    def list_by_resource(self, resource_id: int) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM files WHERE resource_id = ? ORDER BY id", (resource_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_by_id(self, file_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
            return dict(row) if row else None

    def get_by_storage(self, node_id: int, volume_id: int, storage_rel_path: str) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM files
                WHERE node_id = ? AND volume_id = ? AND storage_rel_path = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (node_id, volume_id, storage_rel_path),
            ).fetchone()
            return dict(row) if row else None

    def upsert_from_agent(self, data: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_by_storage(
            node_id=int(data["node_id"]),
            volume_id=int(data["volume_id"]),
            storage_rel_path=str(data["storage_rel_path"]),
        )
        now = utc_now_iso()
        with get_conn() as conn:
            if existing:
                conn.execute(
                    """
                    UPDATE files
                    SET file_name = ?, logical_path = ?, size_mb = ?, owner_id = ?, resource_id = ?, status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        data["file_name"],
                        data["logical_path"],
                        int(data["size_mb"]),
                        int(data["owner_id"]),
                        int(data["resource_id"]),
                        data.get("status", "active"),
                        now,
                        int(existing["id"]),
                    ),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM files WHERE id = ?", (int(existing["id"]),)).fetchone()
                return dict(row)
            cur = conn.execute(
                """
                INSERT INTO files
                (file_name, logical_path, size_mb, owner_id, node_id, volume_id, resource_id, storage_rel_path, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["file_name"],
                    data["logical_path"],
                    int(data["size_mb"]),
                    int(data["owner_id"]),
                    int(data["node_id"]),
                    int(data["volume_id"]),
                    int(data["resource_id"]),
                    data["storage_rel_path"],
                    data.get("status", "active"),
                    now,
                    now,
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM files WHERE id = ?", (cur.lastrowid,)).fetchone()
            return dict(row)

    def update(self, file_id: int, data: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_by_id(file_id)
        if not existing:
            return None
        merged = {**existing, **data}
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE files
                SET file_name = ?, logical_path = ?, storage_rel_path = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    merged["file_name"],
                    merged["logical_path"],
                    merged.get("storage_rel_path"),
                    merged["status"],
                    utc_now_iso(),
                    file_id,
                ),
            )
            conn.commit()
        return self.get_by_id(file_id)

    def update_share_settings(self, file_id: int, share_enabled: bool, share_uuid: str | None) -> dict[str, Any] | None:
        existing = self.get_by_id(file_id)
        if not existing:
            return None
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE files
                SET share_enabled = ?, share_uuid = ?, updated_at = ?
                WHERE id = ?
                """,
                (1 if share_enabled else 0, share_uuid, utc_now_iso(), file_id),
            )
            conn.commit()
        return self.get_by_id(file_id)

    def get_by_share_uuid(self, share_uuid: str) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM files WHERE share_uuid = ? AND share_enabled = 1 LIMIT 1",
                (share_uuid,),
            ).fetchone()
            return dict(row) if row else None

    def has_share_uuid(self, share_uuid: str) -> bool:
        with get_conn() as conn:
            row = conn.execute("SELECT 1 FROM files WHERE share_uuid = ? LIMIT 1", (share_uuid,)).fetchone()
            return bool(row)

    def set_status(self, file_id: int, status: str) -> None:
        with get_conn() as conn:
            conn.execute("UPDATE files SET status = ?, updated_at = ? WHERE id = ?", (status, utc_now_iso(), file_id))
            conn.commit()

    def delete(self, file_id: int) -> bool:
        with get_conn() as conn:
            cur = conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            return cur.rowcount > 0

    def used_size_mb_by_resource(self, resource_id: int) -> int:
        with get_conn() as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(size_mb), 0) AS total_mb
                FROM files
                WHERE resource_id = ?
                  AND status IN ('pending_upload', 'active', 'pending_download', 'archived', 'error')
                """,
                (resource_id,),
            ).fetchone()
            return int(row["total_mb"]) if row else 0

    def used_size_bytes_by_volumes(self, volume_ids: list[int]) -> dict[int, int]:
        ids = sorted({int(v) for v in volume_ids if int(v) > 0})
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        with get_conn() as conn:
            rows = conn.execute(
                f"""
                SELECT volume_id, COALESCE(SUM(size_mb), 0) AS total_mb
                FROM files
                WHERE volume_id IN ({placeholders})
                  AND status IN ('pending_upload', 'active', 'pending_download', 'archived', 'error')
                GROUP BY volume_id
                """,
                tuple(ids),
            ).fetchall()
            return {int(r["volume_id"]): int(r["total_mb"]) * 1024 * 1024 for r in rows}


class AgentJobRepository:
    def create(self, node_id: int, job_type: str, payload: dict) -> dict[str, Any]:
        now = utc_now_iso()
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO agent_jobs (node_id, job_type, payload_json, status, result_json, created_at, updated_at)
                VALUES (?, ?, ?, 'queued', NULL, ?, ?)
                """,
                (node_id, job_type, json.dumps(payload, ensure_ascii=False), now, now),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def get_by_id(self, job_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM agent_jobs WHERE id = ?", (job_id,)).fetchone()
            return dict(row) if row else None

    def fetch_next_for_node(self, node_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM agent_jobs
                WHERE node_id = ? AND status = 'queued'
                ORDER BY id
                LIMIT 1
                """,
                (node_id,),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE agent_jobs SET status='in_progress', updated_at=? WHERE id=?",
                (utc_now_iso(), row["id"]),
            )
            conn.commit()
            updated = conn.execute("SELECT * FROM agent_jobs WHERE id=?", (row["id"],)).fetchone()
            return dict(updated)

    def complete(self, job_id: int, ok: bool, result: dict) -> None:
        status_value = "done" if ok else "failed"
        with get_conn() as conn:
            conn.execute(
                "UPDATE agent_jobs SET status=?, result_json=?, updated_at=? WHERE id=?",
                (status_value, json.dumps(result, ensure_ascii=False), utc_now_iso(), job_id),
            )
            conn.commit()


class TransferBlobRepository:
    def create(self, file_id: int | None, direction: str, node_id: int, local_path: str, size_bytes: int) -> dict[str, Any]:
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO transfer_blobs (file_id, direction, node_id, local_path, size_bytes, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'ready', ?)
                """,
                (file_id, direction, node_id, local_path, size_bytes, utc_now_iso()),
            )
            conn.commit()
            return self.get_by_id(cur.lastrowid)

    def get_by_id(self, blob_id: int) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM transfer_blobs WHERE id = ?", (blob_id,)).fetchone()
            return dict(row) if row else None

    def consume(self, blob_id: int) -> None:
        with get_conn() as conn:
            conn.execute("UPDATE transfer_blobs SET status='consumed' WHERE id=?", (blob_id,))
            conn.commit()

    def latest_ready_for_file(self, file_id: int, direction: str) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM transfer_blobs
                WHERE file_id = ? AND direction = ? AND status = 'ready'
                ORDER BY id DESC
                LIMIT 1
                """,
                (file_id, direction),
            ).fetchone()
            return dict(row) if row else None

    def list_for_file(self, file_id: int) -> list[dict[str, Any]]:
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM transfer_blobs WHERE file_id = ? ORDER BY id DESC", (file_id,)).fetchall()
            return [dict(r) for r in rows]

    def delete_for_file(self, file_id: int) -> None:
        with get_conn() as conn:
            conn.execute("DELETE FROM transfer_blobs WHERE file_id = ?", (file_id,))
            conn.commit()


class AuditLogRepository:
    def create(
        self,
        event_code: str,
        message: str,
        user_id: int | None = None,
        username: str | None = None,
        ip_address: str | None = None,
        actor_type: str = "user",
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_actor = actor_type if actor_type in {"user", "anonymous", "agent", "system"} else "user"
        with get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO audit_logs (user_id, username, ip_address, actor_type, event_code, message, meta_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username,
                    ip_address,
                    normalized_actor,
                    event_code,
                    message,
                    json.dumps(meta or {}, ensure_ascii=False),
                    utc_now_iso(),
                ),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM audit_logs WHERE id = ?", (cur.lastrowid,)).fetchone()
            return dict(row)

    def list(
        self,
        user_id: int | None = None,
        limit: int = 200,
        principal: str = "all",
        include_agents: bool = True,
        ip_query: str | None = None,
    ) -> list[dict[str, Any]]:
        lim = max(1, min(2000, int(limit)))
        with get_conn() as conn:
            conditions: list[str] = []
            params: list[Any] = []
            if user_id is not None:
                conditions.append("user_id = ?")
                params.append(user_id)
            if principal == "auth":
                conditions.append("actor_type = 'user'")
            elif principal == "anon":
                conditions.append("actor_type = 'anonymous'")
            if not include_agents:
                conditions.append("actor_type != 'agent'")
            if ip_query:
                conditions.append("COALESCE(ip_address, '') LIKE ?")
                params.append(f"%{ip_query.strip()}%")
            where_sql = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            sql = f"SELECT * FROM audit_logs {where_sql} ORDER BY id DESC LIMIT ?"
            rows = conn.execute(sql, tuple(params + [lim])).fetchall()
            return [dict(r) for r in rows]


class ServiceSettingsRepository:
    def get(self, key: str) -> dict[str, Any] | None:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM service_settings WHERE key = ?", (key,)).fetchone()
            if not row:
                return None
            return {
                "key": row["key"],
                "value": json.loads(row["value_json"]),
                "updated_at": row["updated_at"],
            }

    def set(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        payload = json.dumps(value, ensure_ascii=False)
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO service_settings (key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
                """,
                (key, payload, now),
            )
            conn.commit()
        return {"key": key, "value": value, "updated_at": now}
