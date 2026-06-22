import argparse
import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from .openpgp_utils import decrypt_json_with_private_key, encrypt_json_for_public_key, ensure_agent_keypair, load_key


@dataclass
class AgentSettings:
    poll_interval_sec: int = 3
    agent_root: str = "./agent_storage"
    agent_name: str = "agent-node-1"
    agent_host: str = "127.0.0.1"
    agent_port: int = 9000
    central_server_url: str = "http://127.0.0.1:8000"
    agent_register_token: str = ""
    agent_keys_dir: str = "./agent_keys"
    agent_state_dir: str = "./agent_state"
    log_level: str = "info"


SETTINGS = AgentSettings()


def _log(msg: str) -> None:
    print(f"[agent] {msg}", flush=True)


def _path_agent_root() -> Path:
    return Path(SETTINGS.agent_root).resolve()


def _path_keys_dir() -> Path:
    return Path(SETTINGS.agent_keys_dir).resolve()


def _path_state_dir() -> Path:
    return Path(SETTINGS.agent_state_dir).resolve()


def _path_agent_private_key() -> Path:
    return _path_keys_dir() / "agent_private.asc"


def _path_agent_public_key() -> Path:
    return _path_keys_dir() / "agent_public.asc"


def _path_server_public_key() -> Path:
    return _path_keys_dir() / "server_public.asc"


def _path_token() -> Path:
    return _path_state_dir() / "agent_token.txt"


def _path_node_id() -> Path:
    return _path_state_dir() / "node_id.txt"


def _safe_volume_path(mount_path: str) -> Path:
    relative = mount_path.strip().lstrip("/").replace("\\", "/")
    root = _path_agent_root()
    full = (root / relative).resolve()
    if root not in full.parents and full != root:
        raise RuntimeError("Invalid mount_path")
    return full


def _volume_meta_path(volume_root: Path) -> Path:
    return volume_root / ".volume_meta.json"


def _calculate_used_bytes(volume_root: Path) -> int:
    total = 0
    for p in volume_root.rglob("*"):
        if not p.is_file():
            continue
        if p.name == ".volume_meta.json":
            continue
        try:
            total += p.stat().st_size
        except OSError:
            continue
    return total


def _refresh_volume_meta(volume_root: Path) -> dict:
    meta_file = _volume_meta_path(volume_root)
    data = {}
    if meta_file.exists():
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
    files_meta = data.get("files")
    if not isinstance(files_meta, list):
        files_meta = []
    valid_files: list[dict] = []
    for item in files_meta:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("storage_rel_path") or "").strip().lstrip("/").replace("\\", "/")
        if not rel:
            continue
        abs_path = (volume_root / rel).resolve()
        if volume_root not in abs_path.parents and abs_path != volume_root:
            continue
        if not abs_path.exists():
            continue
        valid_files.append(item)
    data["files"] = valid_files
    used_bytes = _calculate_used_bytes(volume_root)
    data["used_bytes"] = used_bytes
    data["used_gb"] = used_bytes // (1024**3)
    meta_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def _upsert_volume_file_meta(volume_root: Path, file_meta: dict) -> None:
    data = _refresh_volume_meta(volume_root)
    existing = data.get("files")
    files_meta: list[dict] = existing if isinstance(existing, list) else []
    rel = str(file_meta.get("storage_rel_path") or "").strip().lstrip("/").replace("\\", "/")
    if not rel:
        return
    merged = dict(file_meta)
    merged["storage_rel_path"] = rel
    merged["updated_at"] = int(time.time())
    replaced = False
    for i, row in enumerate(files_meta):
        if str(row.get("storage_rel_path", "")).strip().lstrip("/").replace("\\", "/") == rel:
            files_meta[i] = merged
            replaced = True
            break
    if not replaced:
        files_meta.append(merged)
    data["files"] = files_meta
    _volume_meta_path(volume_root).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _remove_volume_file_meta(volume_root: Path, storage_rel_path: str) -> None:
    data = _refresh_volume_meta(volume_root)
    existing = data.get("files")
    files_meta: list[dict] = existing if isinstance(existing, list) else []
    rel = str(storage_rel_path or "").strip().lstrip("/").replace("\\", "/")
    if not rel:
        return
    data["files"] = [
        row
        for row in files_meta
        if str(row.get("storage_rel_path", "")).strip().lstrip("/").replace("\\", "/") != rel
    ]
    _volume_meta_path(volume_root).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _collect_volumes_meta() -> list[dict]:
    result = []
    for meta_file in _path_agent_root().rglob(".volume_meta.json"):
        try:
            data = _refresh_volume_meta(meta_file.parent)
            if "mount_path" not in data:
                continue
            result.append(
                {
                    "mount_path": data["mount_path"],
                    "used_bytes": int(data.get("used_bytes", 0)),
                    "used_gb": int(data.get("used_gb", 0)),
                    "quota_gb": int(data.get("quota_gb", 0)),
                    "label": data.get("label", ""),
                    "files": data.get("files", []),
                }
            )
        except Exception:
            continue
    return result


def _system_info() -> dict:
    usage = shutil.disk_usage(_path_agent_root())
    total = usage.total
    free = usage.free
    return {
        "os_type": "windows" if os.name == "nt" else "linux",
        "disks": [
            {
                "name": "agent-root",
                "mount": str(_path_agent_root()),
                "total_gb": total // (1024**3),
                "free_gb": free // (1024**3),
            }
        ],
        "volumes": _collect_volumes_meta(),
    }


def _load_config_file(path: str | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise RuntimeError(f"Config file not found: {path}")
    return json.loads(p.read_text(encoding="utf-8"))


def _get_env_or(config: dict, env_name: str, key: str, default):
    return os.getenv(env_name, config.get(key, default))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Alpha storage agent daemon (polling mode)")
    parser.add_argument("--config")
    parser.add_argument("--poll-interval-sec", type=int)
    parser.add_argument("--agent-root")
    parser.add_argument("--agent-name")
    parser.add_argument("--agent-host")
    parser.add_argument("--agent-port", type=int)
    parser.add_argument("--central-server-url")
    parser.add_argument("--agent-register-token")
    parser.add_argument("--agent-keys-dir")
    parser.add_argument("--agent-state-dir")
    parser.add_argument("--log-level")
    return parser.parse_args()


def _apply_settings() -> None:
    global SETTINGS
    args = _parse_args()
    cfg = _load_config_file(args.config)
    SETTINGS = AgentSettings(
        poll_interval_sec=args.poll_interval_sec or int(_get_env_or(cfg, "AGENT_POLL_INTERVAL_SEC", "poll_interval_sec", SETTINGS.poll_interval_sec)),
        agent_root=args.agent_root or _get_env_or(cfg, "AGENT_ROOT", "agent_root", SETTINGS.agent_root),
        agent_name=args.agent_name or _get_env_or(cfg, "AGENT_NAME", "agent_name", SETTINGS.agent_name),
        agent_host=args.agent_host or _get_env_or(cfg, "AGENT_HOST", "agent_host", SETTINGS.agent_host),
        agent_port=args.agent_port or int(_get_env_or(cfg, "AGENT_PORT", "agent_port", SETTINGS.agent_port)),
        central_server_url=args.central_server_url or _get_env_or(cfg, "CENTRAL_SERVER_URL", "central_server_url", SETTINGS.central_server_url),
        agent_register_token=args.agent_register_token
        or _get_env_or(cfg, "AGENT_REGISTER_TOKEN", "agent_register_token", SETTINGS.agent_register_token),
        agent_keys_dir=args.agent_keys_dir or _get_env_or(cfg, "AGENT_KEYS_DIR", "agent_keys_dir", SETTINGS.agent_keys_dir),
        agent_state_dir=args.agent_state_dir or _get_env_or(cfg, "AGENT_STATE_DIR", "agent_state_dir", SETTINGS.agent_state_dir),
        log_level=args.log_level or _get_env_or(cfg, "AGENT_LOG_LEVEL", "log_level", SETTINGS.log_level),
    )


def _read_state() -> tuple[str | None, int | None]:
    token = _path_token().read_text(encoding="utf-8").strip() if _path_token().exists() else None
    node_id = int(_path_node_id().read_text(encoding="utf-8").strip()) if _path_node_id().exists() else None
    return token, node_id


def _write_state(token: str, node_id: int) -> None:
    _path_state_dir().mkdir(parents=True, exist_ok=True)
    _path_token().write_text(token, encoding="utf-8")
    _path_node_id().write_text(str(node_id), encoding="utf-8")


def _register_if_needed() -> tuple[str, int]:
    token, node_id = _read_state()
    if token and node_id:
        return token, node_id
    if not SETTINGS.agent_register_token:
        raise RuntimeError("Agent is not registered and AGENT_REGISTER_TOKEN is not set")

    payload = {
        "name": SETTINGS.agent_name,
        "host": SETTINGS.agent_host,
        "port": SETTINGS.agent_port,
        "agent_public_key": _path_agent_public_key().read_text(encoding="utf-8"),
    }
    headers = {"X-Agent-Registration-Token": SETTINGS.agent_register_token}
    resp = requests.post(SETTINGS.central_server_url.rstrip("/") + "/agent/control/register", json=payload, headers=headers, timeout=10)
    if resp.status_code >= 400:
        raise RuntimeError(f"Register failed: {resp.status_code} {resp.text}")
    body = resp.json()
    token = body["agent_token"]
    node_id = int(body["node_id"])
    _path_server_public_key().parent.mkdir(parents=True, exist_ok=True)
    _path_server_public_key().write_text(body["server_public_key"], encoding="utf-8")
    _write_state(token, node_id)
    _log(f"Registered node_id={node_id}")
    return token, node_id


def _auth_headers(token: str) -> dict:
    return {"X-Agent-Token": token}


def _post_heartbeat(token: str) -> None:
    info = _system_info()
    requests.post(
        SETTINGS.central_server_url.rstrip("/") + "/agent/control/heartbeat",
        json=info,
        headers=_auth_headers(token),
        timeout=8,
    )


def _handle_store_file(token: str, job: dict) -> dict:
    job_id = job["id"]
    payload = job["payload"]
    blob_resp = requests.get(
        SETTINGS.central_server_url.rstrip("/") + f"/agent/control/jobs/{job_id}/download",
        headers=_auth_headers(token),
        stream=True,
        timeout=30,
    )
    if blob_resp.status_code >= 400:
        return {"ok": False, "result": {"error": f"blob download failed: {blob_resp.status_code}"}}
    mount_path = payload.get("volume_mount_path")
    volume_root = _safe_volume_path(mount_path) if mount_path else _path_agent_root()
    relative = str(payload["storage_rel_path"]).lstrip("/").replace("\\", "/")
    target = (volume_root / relative).resolve()
    if volume_root not in target.parents and target != volume_root:
        return {"ok": False, "result": {"error": "invalid storage path"}}
    target.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    with target.open("wb") as out:
        for chunk in blob_resp.iter_content(chunk_size=1024 * 1024):
            if not chunk:
                continue
            out.write(chunk)
            size += len(chunk)
    payload_file_meta = payload.get("file_meta") if isinstance(payload.get("file_meta"), dict) else {}
    _upsert_volume_file_meta(
        volume_root,
        {
            "file_id": payload_file_meta.get("file_id") or payload.get("file_id"),
            "resource_id": payload_file_meta.get("resource_id"),
            "owner_id": payload_file_meta.get("owner_id"),
            "file_name": payload_file_meta.get("file_name") or target.name,
            "logical_path": payload_file_meta.get("logical_path") or ("/" + target.name),
            "size_bytes": int(payload_file_meta.get("size_bytes") or size),
            "size_mb": int(payload_file_meta.get("size_mb") or max(1, size // (1024 * 1024) + (1 if size % (1024 * 1024) else 0))),
            "storage_rel_path": relative,
        },
    )
    _refresh_volume_meta(volume_root)
    return {"ok": True, "result": {"stored_path": str(target), "size_bytes": size}}


def _handle_collect_file(token: str, job: dict) -> dict:
    payload = job["payload"]
    mount_path = payload.get("volume_mount_path")
    volume_root = _safe_volume_path(mount_path) if mount_path else _path_agent_root()
    relative = str(payload["storage_rel_path"]).lstrip("/").replace("\\", "/")
    source = (volume_root / relative).resolve()
    if volume_root not in source.parents and source != volume_root:
        return {"ok": False, "result": {"error": "invalid storage path"}}
    if not source.exists():
        return {"ok": False, "result": {"error": "source file not found"}}
    with source.open("rb") as f:
        files = {"file": (source.name, f, "application/octet-stream")}
        resp = requests.post(
            SETTINGS.central_server_url.rstrip("/") + f"/agent/control/jobs/{job['id']}/upload-result",
            headers=_auth_headers(token),
            files=files,
            timeout=600,
        )
    if resp.status_code >= 400:
        return {"ok": False, "result": {"error": f"upload-result failed: {resp.status_code} {resp.text}"}}
    body = resp.json() if resp.text else {}
    return {"ok": True, "result": {"uploaded": True, "blob_id": body.get("blob_id"), "size_bytes": body.get("size_bytes")}}


def _handle_provision(job: dict) -> dict:
    payload = job["payload"]
    mount = _safe_volume_path(payload["mount_path"])
    mount.mkdir(parents=True, exist_ok=True)
    (mount / ".volume_meta.json").write_text(
        json.dumps(
            {
                "mount_path": payload["mount_path"],
                "label": payload["label"],
                "quota_gb": payload["quota_gb"],
                "quota_bytes": int(payload.get("quota_bytes", int(payload["quota_gb"]) * 1024 * 1024 * 1024)),
                "used_bytes": 0,
                "used_gb": 0,
                "files": [],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"ok": True, "result": {"mount": str(mount)}}


def _handle_delete_file(job: dict) -> dict:
    payload = job["payload"]
    mount_path = payload.get("volume_mount_path")
    volume_root = _safe_volume_path(mount_path) if mount_path else _path_agent_root()
    relative = str(payload["storage_rel_path"]).lstrip("/").replace("\\", "/")
    target = (volume_root / relative).resolve()
    if volume_root not in target.parents and target != volume_root:
        return {"ok": False, "result": {"error": "invalid storage path"}}
    try:
        target.unlink(missing_ok=True)
    except Exception as exc:
        return {"ok": False, "result": {"error": f"delete failed: {exc}"}}
    _remove_volume_file_meta(volume_root, relative)
    _refresh_volume_meta(volume_root)
    return {"ok": True, "result": {"deleted_path": str(target)}}


def _process_job(token: str, job: dict) -> None:
    job_type = job["job_type"]
    payload = job.get("payload")
    if payload is None and job.get("payload_encrypted"):
        payload = decrypt_json_with_private_key(load_key(_path_agent_private_key()), job["payload_encrypted"])
    job = {**job, "payload": payload or {}}
    if job_type == "store_file":
        result = _handle_store_file(token, job)
    elif job_type == "collect_file":
        result = _handle_collect_file(token, job)
    elif job_type == "provision_volume":
        result = _handle_provision(job)
    elif job_type == "delete_file":
        result = _handle_delete_file(job)
    else:
        result = {"ok": False, "result": {"error": f"unknown job_type {job_type}"}}

    encrypted_result = encrypt_json_for_public_key(
        _path_server_public_key().read_text(encoding="utf-8"),
        result,
    )
    requests.post(
        SETTINGS.central_server_url.rstrip("/") + f"/agent/control/jobs/{job['id']}/complete",
        headers=_auth_headers(token),
        json={"encrypted_result": encrypted_result},
        timeout=10,
    )


def run() -> None:
    _apply_settings()
    _path_agent_root().mkdir(parents=True, exist_ok=True)
    ensure_agent_keypair(_path_agent_private_key(), _path_agent_public_key())
    token, _ = _register_if_needed()
    _log("Agent daemon started (polling mode)")

    while True:
        try:
            _post_heartbeat(token)
            resp = requests.post(
                SETTINGS.central_server_url.rstrip("/") + "/agent/control/jobs/fetch",
                headers=_auth_headers(token),
                timeout=10,
            )
            if resp.status_code < 400:
                body = resp.json()
                job = body.get("job")
                if job:
                    _process_job(token, job)
        except Exception as exc:
            _log(f"loop error: {exc}")
        time.sleep(max(1, SETTINGS.poll_interval_sec))


if __name__ == "__main__":
    run()
