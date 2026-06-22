import json
import shlex
import subprocess
import urllib.error
import urllib.request

from fastapi import HTTPException, status

from .config import AGENT_TIMEOUT_SEC
from .openpgp_utils import decrypt_json_with_private_key, encrypt_json_for_public_key, load_server_private_key


class NodeConnector:
    def check(self, node: dict) -> tuple[bool, str]:
        raise NotImplementedError

    def provision_volume(self, node: dict, mount_path: str, quota_gb: int, label: str) -> tuple[bool, str]:
        raise NotImplementedError

    def system_info(self, node: dict) -> dict:
        raise NotImplementedError


class AgentConnector(NodeConnector):
    def _call_plain(self, node: dict, endpoint: str, payload: dict) -> dict:
        if not node.get("agent_url"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_url is required")
        url = node["agent_url"].rstrip("/") + endpoint
        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT_SEC) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.URLError as exc:
            return {"ok": False, "message": f"agent error: {exc}"}
        except json.JSONDecodeError:
            return {"ok": False, "message": "agent returned non-JSON response"}

    def _call(self, node: dict, endpoint: str, payload: dict) -> dict:
        # If we have agent public key, use encrypted command channel.
        if node.get("agent_public_key"):
            try:
                encrypted = encrypt_json_for_public_key(
                    node["agent_public_key"],
                    {"endpoint": endpoint, "payload": payload},
                )
                response = self._call_plain(node, "/agent/secure/execute", {"encrypted": encrypted})
                if not response.get("ok") or "encrypted" not in response:
                    return {"ok": False, "message": response.get("message", "secure channel error")}
                decrypted = decrypt_json_with_private_key(load_server_private_key(), response["encrypted"])
                return decrypted
            except Exception as exc:
                # Compatibility fallback for agents not yet upgraded to secure endpoint.
                plain = self._call_plain(node, endpoint, payload)
                if plain.get("ok"):
                    return plain
                return {"ok": False, "message": f"secure channel failed: {exc}; plain: {plain.get('message')}"}
        return self._call_plain(node, endpoint, payload)

    def check(self, node: dict) -> tuple[bool, str]:
        result = self._call(node, "/agent/ping", {})
        return bool(result.get("ok")), str(result.get("message", ""))

    def provision_volume(self, node: dict, mount_path: str, quota_gb: int, label: str) -> tuple[bool, str]:
        result = self._call(
            node,
            "/agent/volume/provision",
            {"mount_path": mount_path, "quota_gb": quota_gb, "label": label},
        )
        return bool(result.get("ok")), str(result.get("message", ""))

    def system_info(self, node: dict) -> dict:
        result = self._call(node, "/agent/system/info", {})
        if not result.get("ok"):
            return {"ok": False, "message": str(result.get("message", "agent error"))}
        return result


class SSHConnector(NodeConnector):
    def _ssh_command(self, node: dict, remote_command: str) -> list[str]:
        username = node.get("ssh_username")
        if not username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ssh_username is required")
        host = node["host"]
        port = str(node.get("port", 22))
        target = f"{username}@{host}"
        cmd = ["ssh", "-p", port]
        if node.get("ssh_key_path"):
            cmd.extend(["-i", node["ssh_key_path"]])
        cmd.extend([target, remote_command])
        return cmd

    def _run(self, cmd: list[str]) -> tuple[bool, str]:
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=AGENT_TIMEOUT_SEC + 4, check=False)
        except FileNotFoundError:
            return False, "ssh client is not installed on control server"
        except subprocess.TimeoutExpired:
            return False, "ssh command timed out"
        if completed.returncode != 0:
            details = completed.stderr.strip() or completed.stdout.strip() or f"exit code {completed.returncode}"
            return False, details
        return True, completed.stdout.strip() or "ok"

    def _run_raw(self, cmd: list[str]) -> tuple[bool, str]:
        return self._run(cmd)

    def check(self, node: dict) -> tuple[bool, str]:
        cmd = self._ssh_command(node, "echo ssh_ok")
        return self._run(cmd)

    def provision_volume(self, node: dict, mount_path: str, quota_gb: int, label: str) -> tuple[bool, str]:
        safe_path = shlex.quote(mount_path)
        safe_label = shlex.quote(label)
        safe_quota = int(quota_gb)
        remote = (
            f"mkdir -p {safe_path} && "
            f"printf 'label={safe_label}\\nquota_gb={safe_quota}\\n' > {safe_path}/.volume_meta"
        )
        cmd = self._ssh_command(node, remote)
        return self._run(cmd)

    def system_info(self, node: dict) -> dict:
        ok_uname, uname = self._run_raw(self._ssh_command(node, "uname -s"))
        if ok_uname and ("linux" in uname.lower() or "darwin" in uname.lower()):
            ok_df, df_out = self._run_raw(self._ssh_command(node, "df -kP"))
            if not ok_df:
                return {"ok": False, "message": df_out}
            lines = [ln for ln in df_out.splitlines() if ln.strip()]
            disks = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    total_k = int(parts[1])
                    avail_k = int(parts[3])
                    disks.append(
                        {
                            "name": parts[0],
                            "mount": parts[5],
                            "total_gb": total_k // (1024 * 1024),
                            "free_gb": avail_k // (1024 * 1024),
                        }
                    )
            return {"ok": True, "os_type": "linux", "disks": disks}

        ok_win, win_json = self._run_raw(
            self._ssh_command(
                node,
                "powershell -NoProfile -Command \"Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free | ConvertTo-Json -Compress\"",
            )
        )
        if not ok_win:
            return {"ok": False, "message": f"Cannot detect OS: {win_json}"}
        try:
            data = json.loads(win_json)
            drives = data if isinstance(data, list) else [data]
            disks = []
            for d in drives:
                total = int(d.get("Used", 0)) + int(d.get("Free", 0))
                disks.append(
                    {
                        "name": str(d.get("Name", "")),
                        "mount": f"{d.get('Name', '')}:\\",
                        "total_gb": total // (1024**3),
                        "free_gb": int(d.get("Free", 0)) // (1024**3),
                    }
                )
            return {"ok": True, "os_type": "windows", "disks": disks}
        except Exception:
            return {"ok": False, "message": "Cannot parse windows disk info"}


def connector_for(node: dict) -> NodeConnector:
    if node["connection_type"] == "agent":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Direct connector for agent nodes is disabled. Use agent polling control API.",
        )
    if node["connection_type"] == "ssh":
        return SSHConnector()
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported connection type")
