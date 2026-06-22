import sqlite3
from contextlib import contextmanager

from .config import DB_PATH


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return bool(row)


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    if not _table_exists(conn, table_name):
        return set()
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {r[1] for r in rows}


def _ensure_column(conn: sqlite3.Connection, table_name: str, definition: str) -> None:
    column_name = definition.split()[0]
    if column_name not in _table_columns(conn, table_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {definition}")


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'employee', 'client')),
                created_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(conn, "users", "admin_level TEXT NOT NULL DEFAULT 'none'")
        _ensure_column(conn, "users", "admin_scope_group_id INTEGER")
        _ensure_column(conn, "users", "is_blocked INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS groups_acl (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                code TEXT UNIQUE NOT NULL,
                group_type TEXT NOT NULL,
                parent_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY(parent_id) REFERENCES groups_acl(id) ON DELETE SET NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_groups (
                user_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(group_id) REFERENCES groups_acl(id) ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                code TEXT UNIQUE NOT NULL,
                path TEXT UNIQUE NOT NULL,
                resource_type TEXT NOT NULL,
                size_limit_mb INTEGER NOT NULL DEFAULT 0,
                parent_id INTEGER,
                is_hidden INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(parent_id) REFERENCES resources(id) ON DELETE SET NULL
            )
            """
        )
        _ensure_column(conn, "resources", "size_limit_mb INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resource_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id INTEGER NOT NULL,
                folder_path TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(resource_id, folder_path),
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE,
                FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resource_nodes (
                resource_id INTEGER NOT NULL,
                node_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (resource_id, node_id),
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE,
                FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS group_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                resource_id INTEGER,
                permission_code TEXT NOT NULL,
                allow INTEGER NOT NULL CHECK(allow IN (0,1)),
                created_at TEXT NOT NULL,
                UNIQUE(group_id, resource_id, permission_code),
                FOREIGN KEY(group_id) REFERENCES groups_acl(id) ON DELETE CASCADE,
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                connection_type TEXT NOT NULL CHECK(connection_type IN ('agent', 'ssh')),
                agent_url TEXT,
                ssh_username TEXT,
                ssh_password TEXT,
                ssh_key_path TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                last_seen TEXT,
                agent_public_key TEXT,
                agent_token TEXT,
                os_type TEXT,
                disks_json TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(conn, "nodes", "agent_public_key TEXT")
        _ensure_column(conn, "nodes", "agent_token TEXT")
        _ensure_column(conn, "nodes", "os_type TEXT")
        _ensure_column(conn, "nodes", "disks_json TEXT")
        _ensure_column(conn, "nodes", "storage_priority INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "nodes", "store_all_data INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS volumes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id INTEGER NOT NULL,
                mount_path TEXT NOT NULL,
                label TEXT NOT NULL,
                quota_gb INTEGER NOT NULL,
                quota_bytes INTEGER NOT NULL DEFAULT 0,
                used_gb INTEGER NOT NULL DEFAULT 0,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                UNIQUE(node_id, mount_path),
                FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
            )
            """
        )
        _ensure_column(conn, "volumes", "used_bytes INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "volumes", "quota_bytes INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            """
            UPDATE volumes
            SET quota_bytes = CASE
                WHEN quota_bytes IS NULL OR quota_bytes <= 0
                THEN quota_gb * 1024 * 1024 * 1024
                ELSE quota_bytes
            END
            """
        )

        files_columns = _table_columns(conn, "files")
        required_file_columns = {"logical_path", "volume_id", "resource_id", "storage_rel_path"}
        if files_columns and not required_file_columns.issubset(files_columns):
            if _table_exists(conn, "files_legacy"):
                conn.execute("DROP TABLE files")
            else:
                conn.execute("ALTER TABLE files RENAME TO files_legacy")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                logical_path TEXT NOT NULL,
                size_mb INTEGER NOT NULL,
                owner_id INTEGER NOT NULL,
                node_id INTEGER NOT NULL,
                volume_id INTEGER NOT NULL,
                resource_id INTEGER NOT NULL,
                storage_rel_path TEXT,
                share_enabled INTEGER NOT NULL DEFAULT 0,
                share_uuid TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending_upload', 'active', 'pending_download', 'archived', 'deleted', 'error')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id),
                FOREIGN KEY(node_id) REFERENCES nodes(id),
                FOREIGN KEY(volume_id) REFERENCES volumes(id),
                FOREIGN KEY(resource_id) REFERENCES resources(id)
            )
            """
        )
        _ensure_column(conn, "files", "share_enabled INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "files", "share_uuid TEXT")
        conn.execute("UPDATE files SET share_enabled = 0 WHERE share_enabled IS NULL")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_share_uuid ON files(share_uuid)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id INTEGER NOT NULL,
                job_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('queued', 'in_progress', 'done', 'failed')) DEFAULT 'queued',
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transfer_blobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER,
                direction TEXT NOT NULL CHECK(direction IN ('to_agent', 'from_agent')),
                node_id INTEGER NOT NULL,
                local_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ready', 'consumed', 'failed')) DEFAULT 'ready',
                created_at TEXT NOT NULL,
                FOREIGN KEY(file_id) REFERENCES files(id),
                FOREIGN KEY(node_id) REFERENCES nodes(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                ip_address TEXT,
                actor_type TEXT NOT NULL DEFAULT 'user',
                event_code TEXT NOT NULL,
                message TEXT NOT NULL,
                meta_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )
        _ensure_column(conn, "audit_logs", "ip_address TEXT")
        _ensure_column(conn, "audit_logs", "actor_type TEXT NOT NULL DEFAULT 'user'")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS service_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()
