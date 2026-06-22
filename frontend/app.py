import os
from functools import wraps
from pathlib import PurePosixPath
from urllib.parse import urlencode

import requests
from flask import Flask, Response, flash, has_request_context, jsonify, redirect, render_template, request, session, stream_with_context, url_for


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "costor-flask-secret")
    app.config["BACKEND_URL"] = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

    def api_call(method: str, path: str, *, json=None, params=None, data=None, files=None):
        token = session.get("token")
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if has_request_context():
            xff = (request.headers.get("X-Forwarded-For") or "").strip()
            x_real_ip = (request.headers.get("X-Real-IP") or "").strip()
            client_ip = xff or x_real_ip or (request.remote_addr or "")
            if client_ip:
                headers["X-Forwarded-For"] = client_ip
                headers["X-Real-IP"] = client_ip.split(",", 1)[0].strip()
            user_agent = (request.headers.get("User-Agent") or "").strip()
            if user_agent:
                headers["User-Agent"] = user_agent
                headers["X-Original-User-Agent"] = user_agent
        url = app.config["BACKEND_URL"].rstrip("/") + path
        response = requests.request(
            method,
            url,
            json=json,
            params=params,
            data=data,
            files=files,
            headers=headers,
            timeout=30,
        )
        payload = {}
        if response.text:
            try:
                payload = response.json()
            except Exception:
                payload = {"raw": response.text}
        if response.status_code >= 400:
            message = payload.get("detail") if isinstance(payload, dict) else str(payload)
            raise RuntimeError(f"{response.status_code}: {message}")
        return payload

    def normalize_folder(folder: str | None) -> str:
        if not folder:
            return "/"
        p = folder.strip()
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p[:-1]
        return p or "/"

    def parent_folder(folder: str) -> str | None:
        f = normalize_folder(folder)
        if f == "/":
            return None
        parent = str(PurePosixPath(f).parent)
        return "/" if parent == "." else parent

    def build_breadcrumbs(folder: str) -> list[dict]:
        f = normalize_folder(folder)
        if f == "/":
            return [{"name": "Root", "path": "/"}]
        parts = [p for p in f.split("/") if p]
        out = [{"name": "Root", "path": "/"}]
        cur = ""
        for part in parts:
            cur += "/" + part
            out.append({"name": part, "path": cur})
        return out

    def immediate_subfolders(files: list[dict], explicit_folders: list[str], current_folder: str) -> list[str]:
        current = normalize_folder(current_folder)
        prefix = "/" if current == "/" else current + "/"
        result = set()
        for f in files:
            parent = str(PurePosixPath(f.get("logical_path", "/")).parent)
            parent = "/" if parent == "." else parent
            if parent == current:
                continue
            if parent.startswith(prefix):
                rest = parent[len(prefix) :]
                if rest:
                    first = rest.split("/")[0]
                    result.add((prefix if prefix != "/" else "/") + first)
        for folder in explicit_folders:
            normalized_folder = normalize_folder(folder)
            if normalized_folder == current:
                continue
            if normalized_folder.startswith(prefix):
                rest = normalized_folder[len(prefix) :]
                if rest:
                    first = rest.split("/")[0]
                    result.add((prefix if prefix != "/" else "/") + first)
        return sorted(result)

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("token"):
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapper

    def admin_panel_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("token"):
                return redirect(url_for("login"))
            perms = session.get("permissions", [])
            if "admin_panel" not in perms:
                flash("No access to admin panel", "danger")
                return redirect(url_for("drive"))
            return view(*args, **kwargs)

        return wrapper

    def refresh_profile():
        me = api_call("GET", "/auth/me")
        perm_data = api_call("GET", "/acl/me/permissions")
        session["me"] = me
        session["permissions"] = perm_data.get("permissions", [])
        session["is_admin"] = bool(perm_data.get("is_admin"))
        return me, perm_data

    def admin_data() -> dict:
        return api_call("GET", "/acl/admin/management")

    def drive_query_from_request() -> str:
        query = urlencode(
            {
                k: v
                for k, v in {
                    "resource_id": request.args.get("resource_id") or request.form.get("resource_id"),
                    "folder": request.args.get("folder") or request.form.get("current_folder"),
                }.items()
                if v
            }
        )
        return f"?{query}" if query else ""

    @app.context_processor
    def inject_user():
        return {
            "me": session.get("me"),
            "permissions": session.get("permissions", []),
            "is_admin": session.get("is_admin", False),
        }

    @app.get("/")
    def root():
        if session.get("token"):
            return redirect(url_for("drive"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            try:
                data = api_call("POST", "/auth/login", json={"username": username, "password": password})
                session["token"] = data["access_token"]
                refresh_profile()
                return redirect(url_for("drive"))
            except Exception as exc:
                flash(f"Login error: {exc}", "danger")
        return render_template("login.html")

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/drive")
    @login_required
    def drive():
        try:
            me, _ = refresh_profile()
            resources = api_call("GET", "/acl/resources")
            files = api_call("GET", "/files")

            selected_resource_id = request.args.get("resource_id", type=int)
            if not selected_resource_id and resources:
                selected_resource_id = resources[0]["id"]
            if selected_resource_id:
                files = [f for f in files if f["resource_id"] == selected_resource_id]
                selected_res = next((r for r in resources if r["id"] == selected_resource_id), None)
                try:
                    if selected_res:
                        api_call(
                            "POST",
                            "/audit/event",
                            json={
                                "event_code": "open_resource",
                                "message": f"Opened resource {selected_res['name']}",
                                "meta": {"resource_id": selected_resource_id, "path": selected_res.get("path", "")},
                            },
                        )
                except Exception:
                    pass
            explicit_folders: list[str] = []
            if selected_resource_id:
                folder_rows = api_call("GET", f"/acl/resources/{selected_resource_id}/folders")
                explicit_folders = [f["folder_path"] for f in folder_rows]

            current_folder = normalize_folder(request.args.get("folder", "/"))
            files_current = []
            for f in files:
                parent = str(PurePosixPath(f.get("logical_path", "/")).parent)
                parent = "/" if parent == "." else parent
                if parent == current_folder:
                    files_current.append(f)

            folders = immediate_subfolders(files, explicit_folders, current_folder)
            return render_template(
                "drive.html",
                me=me,
                resources=resources,
                files=files_current,
                folders=folders,
                current_folder=current_folder,
                breadcrumbs=build_breadcrumbs(current_folder),
                parent_folder=parent_folder(current_folder),
                selected_resource_id=selected_resource_id,
            )
        except Exception as exc:
            flash(f"Data load error: {exc}", "danger")
            return render_template(
                "drive.html",
                resources=[],
                files=[],
                folders=[],
                current_folder="/",
                breadcrumbs=[{"name": "Root", "path": "/"}],
                parent_folder=None,
                selected_resource_id=None,
            )

    @app.post("/drive/folders/create")
    @login_required
    def create_folder():
        form = request.form
        try:
            resource_id = int(form.get("resource_id", "0"))
            current_folder = normalize_folder(form.get("current_folder", "/"))
            folder_name = form.get("folder_name", "").strip()
            if not folder_name:
                raise RuntimeError("Folder name is required")
            folder_path = (current_folder.rstrip("/") + "/" + folder_name) if current_folder != "/" else f"/{folder_name}"
            api_call("POST", "/acl/folders", json={"resource_id": resource_id, "folder_path": folder_path})
            flash("Folder created", "success")
        except Exception as exc:
            flash(f"Create folder error: {exc}", "danger")
        return redirect(url_for("drive") + drive_query_from_request())

    @app.post("/drive/files/upload")
    @login_required
    def upload_file():
        resource_id = request.form.get("resource_id", "").strip()
        current_folder = normalize_folder(request.form.get("current_folder", "/"))
        uploads = [f for f in request.files.getlist("file") if f and f.filename]
        if not resource_id or not uploads:
            flash("Choose resource and files", "danger")
            return redirect(url_for("drive"))
        ok_count = 0
        errors: list[str] = []
        for upload in uploads:
            logical_path = (current_folder.rstrip("/") + "/" + upload.filename) if current_folder != "/" else f"/{upload.filename}"
            try:
                api_call(
                    "POST",
                    "/files/upload",
                    data={"resource_id": resource_id, "logical_path": logical_path},
                    files={"file": (upload.filename, upload.stream, upload.mimetype)},
                )
                ok_count += 1
            except Exception as exc:
                errors.append(f"{upload.filename}: {exc}")
        if ok_count:
            flash(f"Uploaded {ok_count} file(s)", "success")
        if errors:
            preview = "; ".join(errors[:3])
            tail = " ..." if len(errors) > 3 else ""
            flash(f"Upload errors ({len(errors)}): {preview}{tail}", "danger")
        return redirect(url_for("drive") + f"?{urlencode({'resource_id': resource_id, 'folder': current_folder})}")

    @app.post("/drive/files/<int:file_id>/delete")
    @login_required
    def delete_file(file_id: int):
        try:
            api_call("DELETE", f"/files/{file_id}")
            flash("File deleted", "success")
        except Exception as exc:
            flash(f"Delete file error: {exc}", "danger")
        return redirect(url_for("drive") + drive_query_from_request())

    @app.get("/drive/files/<int:file_id>/prepare-download")
    @login_required
    def prepare_download(file_id: int):
        try:
            api_call("POST", f"/files/{file_id}/prepare-download")
            flash("Download requested from node. Retry in a few seconds.", "success")
        except Exception as exc:
            flash(f"Prepare download error: {exc}", "danger")
        query = urlencode({k: v for k, v in {"resource_id": request.args.get("resource_id"), "folder": request.args.get("folder")}.items() if v})
        return redirect(url_for("drive") + (f"?{query}" if query else ""))

    @app.get("/drive/files/<int:file_id>/download")
    @login_required
    def download_file(file_id: int):
        token = session.get("token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        xff = (request.headers.get("X-Forwarded-For") or "").strip()
        x_real_ip = (request.headers.get("X-Real-IP") or "").strip()
        client_ip = xff or x_real_ip or (request.remote_addr or "")
        if client_ip:
            headers["X-Forwarded-For"] = client_ip
            headers["X-Real-IP"] = client_ip.split(",", 1)[0].strip()
        user_agent = (request.headers.get("User-Agent") or "").strip()
        if user_agent:
            headers["User-Agent"] = user_agent
            headers["X-Original-User-Agent"] = user_agent
        url = app.config["BACKEND_URL"].rstrip("/") + f"/files/{file_id}/download"
        resp = requests.get(url, headers=headers, stream=True, timeout=600)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except Exception:
                detail = resp.text
            flash(f"Download unavailable: {detail}", "danger")
            return redirect(url_for("drive"))

        filename = "download.bin"
        cd = resp.headers.get("content-disposition", "")
        if "filename=" in cd:
            filename = cd.split("filename=")[-1].strip("\"'")

        def gen():
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    yield chunk

        return Response(
            stream_with_context(gen()),
            mimetype=resp.headers.get("content-type", "application/octet-stream"),
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/drive/files/<int:file_id>/share")
    @login_required
    def drive_file_share_info(file_id: int):
        try:
            payload = api_call("GET", f"/files/{file_id}/share")
            share_uuid = payload.get("share_uuid")
            share_url = url_for("private_download", share_uuid=share_uuid, _external=True) if payload.get("enabled") and share_uuid else None
            return jsonify({"ok": True, "enabled": bool(payload.get("enabled")), "share_url": share_url})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/drive/files/<int:file_id>/share")
    @login_required
    def drive_file_share_update(file_id: int):
        try:
            payload = request.get_json(silent=True) or {}
            enabled = bool(payload.get("enabled", False))
            result = api_call("PUT", f"/files/{file_id}/share", json={"enabled": enabled})
            share_uuid = result.get("share_uuid")
            share_url = url_for("private_download", share_uuid=share_uuid, _external=True) if result.get("enabled") and share_uuid else None
            return jsonify({"ok": True, "enabled": bool(result.get("enabled")), "share_url": share_url})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.get("/private/<string:share_uuid>/download")
    def private_download(share_uuid: str):
        headers = {}
        xff = (request.headers.get("X-Forwarded-For") or "").strip()
        x_real_ip = (request.headers.get("X-Real-IP") or "").strip()
        client_ip = xff or x_real_ip or (request.remote_addr or "")
        if client_ip:
            headers["X-Forwarded-For"] = client_ip
            headers["X-Real-IP"] = client_ip.split(",", 1)[0].strip()
        user_agent = (request.headers.get("User-Agent") or "").strip()
        if user_agent:
            headers["User-Agent"] = user_agent
            headers["X-Original-User-Agent"] = user_agent
        url = app.config["BACKEND_URL"].rstrip("/") + f"/private/{share_uuid}/download"
        resp = requests.get(url, headers=headers, stream=True, timeout=600)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except Exception:
                detail = resp.text
            return Response(detail or "Download unavailable", status=resp.status_code, mimetype="text/plain; charset=utf-8")

        filename = "download.bin"
        cd = resp.headers.get("content-disposition", "")
        if "filename=" in cd:
            filename = cd.split("filename=")[-1].strip("\"'")

        def gen():
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    yield chunk

        return Response(
            stream_with_context(gen()),
            mimetype=resp.headers.get("content-type", "application/octet-stream"),
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/admin")
    @admin_panel_required
    def admin_dashboard():
        try:
            refresh_profile()
            dashboard = api_call("GET", "/admin/dashboard")
            capabilities = api_call("GET", "/admin/capabilities")
            return render_template("admin_dashboard.html", dashboard=dashboard, capabilities=capabilities)
        except Exception as exc:
            flash(f"Dashboard error: {exc}", "danger")
            return render_template("admin_dashboard.html", dashboard=None, capabilities={})

    @app.get("/admin/audit")
    @admin_panel_required
    def admin_audit():
        try:
            refresh_profile()
            users = api_call("GET", "/auth/users")
            selected_user_id = request.args.get("user_id", type=int)
            principal = request.args.get("principal", "all")
            if principal not in ("all", "auth", "anon"):
                principal = "all"
            include_agents_arg = request.args.getlist("include_agents")
            include_agents = (include_agents_arg[-1] if include_agents_arg else "1") != "0"
            ip_query = (request.args.get("ip_query") or "").strip()
            params = {"limit": 500}
            if selected_user_id:
                params["user_id"] = selected_user_id
            params["principal"] = principal
            params["include_agents"] = 1 if include_agents else 0
            if ip_query:
                params["ip_query"] = ip_query
            data = api_call("GET", "/admin/audit", params=params)
            return render_template(
                "admin_audit.html",
                logs=data.get("items", []),
                users=users,
                selected_user_id=selected_user_id,
                principal=principal,
                include_agents=include_agents,
                ip_query=ip_query,
            )
        except Exception as exc:
            flash(f"Audit page error: {exc}", "danger")
            return redirect(url_for("admin_dashboard"))

    @app.get("/admin/settings")
    @admin_panel_required
    def admin_settings():
        try:
            refresh_profile()
            resources = api_call("GET", "/acl/resources")
            data = api_call("GET", "/admin/settings")
            archive = (data or {}).get("user_archive", {})
            return render_template("admin_settings.html", resources=resources, archive=archive)
        except Exception as exc:
            flash(f"Settings page error: {exc}", "danger")
            return redirect(url_for("admin_dashboard"))

    @app.post("/admin/settings")
    @admin_panel_required
    def admin_settings_save():
        form = request.form
        try:
            payload = {
                "enabled": bool(form.get("enabled")),
                "resource_id": int(form["resource_id"]) if form.get("resource_id") else None,
                "folder_path": form.get("folder_path", "/archives").strip() or "/archives",
                "download_timeout_sec": int(form.get("download_timeout_sec", "120") or 120),
            }
            api_call("PUT", "/admin/settings", json=payload)
            flash("Settings saved", "success")
        except Exception as exc:
            flash(f"Save settings error: {exc}", "danger")
        return redirect(url_for("admin_settings"))

    @app.post("/admin/nodes/create")
    @admin_panel_required
    def create_node():
        form = request.form
        payload = {
            "name": form.get("name", ""),
            "host": form.get("host", ""),
            "port": int(form.get("port", "22")),
            "connection_type": form.get("connection_type", "agent"),
            "agent_url": form.get("agent_url") or None,
            "ssh_username": form.get("ssh_username") or None,
            "ssh_password": form.get("ssh_password") or None,
            "ssh_key_path": form.get("ssh_key_path") or None,
            "storage_priority": int(form.get("storage_priority", "0") or 0),
            "store_all_data": bool(form.get("store_all_data")),
        }
        try:
            api_call("POST", "/nodes", json=payload)
            flash("Node added", "success")
        except Exception as exc:
            flash(f"Add node error: {exc}", "danger")
        return redirect(url_for("admin_dashboard"))

    @app.get("/admin/nodes/<int:node_id>")
    @admin_panel_required
    def admin_node_detail(node_id: int):
        try:
            refresh_profile()
            detail = api_call("GET", f"/admin/nodes/{node_id}/detail")
            return render_template("admin_node.html", detail=detail)
        except Exception as exc:
            flash(f"Node detail error: {exc}", "danger")
            return redirect(url_for("admin_dashboard"))

    @app.post("/admin/nodes/<int:node_id>/settings")
    @admin_panel_required
    def update_node_settings(node_id: int):
        try:
            payload = {
                "storage_priority": int(request.form.get("storage_priority", "0") or 0),
                "store_all_data": bool(request.form.get("store_all_data")),
            }
            api_call("PUT", f"/nodes/{node_id}", json=payload)
            flash("Node storage settings updated", "success")
        except Exception as exc:
            flash(f"Update node settings error: {exc}", "danger")
        return redirect(url_for("admin_node_detail", node_id=node_id))

    @app.post("/admin/nodes/<int:node_id>/volumes/create")
    @admin_panel_required
    def create_volume(node_id: int):
        form = request.form
        try:
            quota_value_raw = (form.get("quota_value", "") or "").strip().replace(",", ".")
            quota_unit = (form.get("quota_unit", "GB") or "GB").strip().upper()
            quota_value = float(quota_value_raw)
            if quota_value <= 0:
                raise ValueError("quota_non_positive")
            unit_map = {"MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
            if quota_unit not in unit_map:
                raise ValueError("quota_bad_unit")
            quota_bytes = int(quota_value * unit_map[quota_unit])
            if quota_bytes <= 0:
                raise ValueError("quota_too_small")
            payload = {
                "node_id": node_id,
                "mount_path": form.get("mount_path", "").strip(),
                "label": form.get("label", "").strip(),
                "quota_bytes": quota_bytes,
            }
            if not payload["mount_path"] or not payload["label"]:
                raise ValueError("missing_fields")
            api_call("POST", "/volumes", json=payload)
            flash("Volume added", "success")
        except ValueError:
            flash("Некорректно введены данные тома. Проверьте путь, label и размер (число + единица MB/GB/TB).", "danger")
        except Exception as exc:
            flash(f"Add volume error: {exc}", "danger")
        return redirect(url_for("admin_node_detail", node_id=node_id))

    @app.post("/admin/volumes/<int:volume_id>/delete")
    @admin_panel_required
    def delete_volume(volume_id: int):
        node_id = int(request.form.get("node_id", "0") or 0)
        try:
            api_call("DELETE", f"/volumes/{volume_id}")
            flash("Volume deleted", "success")
        except Exception as exc:
            flash(f"Delete volume error: {exc}", "danger")
        if node_id:
            return redirect(url_for("admin_node_detail", node_id=node_id))
        return redirect(url_for("admin_dashboard"))

    @app.get("/admin/nodes/<int:node_id>/check")
    @admin_panel_required
    def check_node(node_id: int):
        try:
            result = api_call("POST", f"/nodes/{node_id}/check")
            flash(f"Node check: {result.get('message', 'ok')}", "success" if result.get("ok") else "danger")
        except Exception as exc:
            flash(f"Node check error: {exc}", "danger")
        return redirect(url_for("admin_node_detail", node_id=node_id))

    @app.post("/admin/nodes/<int:node_id>/delete")
    @admin_panel_required
    def delete_node(node_id: int):
        try:
            api_call("DELETE", f"/nodes/{node_id}")
            flash("Node deleted", "success")
        except Exception as exc:
            flash(f"Delete node error: {exc}", "danger")
        return redirect(url_for("admin_dashboard"))

    @app.get("/admin/users")
    @admin_panel_required
    def admin_users():
        try:
            refresh_profile()
            users = api_call("GET", "/auth/users")
            groups = api_call("GET", "/acl/groups")
            return render_template("admin_users.html", users=users, groups=groups, current_user_id=session.get("me", {}).get("id"))
        except Exception as exc:
            flash(f"Users page error: {exc}", "danger")
            return redirect(url_for("admin_dashboard"))

    @app.post("/admin/users/create")
    @admin_panel_required
    def admin_create_user():
        form = request.form
        try:
            payload = {
                "username": form.get("username", "").strip(),
                "password": form.get("password", "").strip(),
                "role": form.get("role", "employee").strip(),
                "admin_level": form.get("admin_level", "none").strip(),
                "admin_scope_group_id": int(form["admin_scope_group_id"]) if form.get("admin_scope_group_id") else None,
            }
            api_call("POST", "/auth/users", json=payload)
            flash("User created", "success")
        except Exception as exc:
            flash(f"Create user error: {exc}", "danger")
        return redirect(url_for("admin_users"))

    @app.get("/admin/users/<int:user_id>/edit")
    @admin_panel_required
    def admin_edit_user_page(user_id: int):
        try:
            refresh_profile()
            data = admin_data()
            users = data.get("users", [])
            groups = data.get("groups", [])
            user_groups = data.get("user_groups", [])
            user = next((u for u in users if u["id"] == user_id), None)
            if not user:
                flash("User not found", "danger")
                return redirect(url_for("admin_users"))
            member_group_ids = {ug["group_id"] for ug in user_groups if ug["user_id"] == user_id}
            member_groups = [g for g in groups if g["id"] in member_group_ids]
            available_groups = [g for g in groups if g["id"] not in member_group_ids]
            return render_template(
                "admin_user_edit.html",
                user=user,
                groups=groups,
                member_groups=member_groups,
                available_groups=available_groups,
            )
        except Exception as exc:
            flash(f"Edit user page error: {exc}", "danger")
            return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/edit")
    @admin_panel_required
    def admin_edit_user(user_id: int):
        form = request.form
        try:
            payload = {
                "username": form.get("username", "").strip(),
                "role": form.get("role", "employee").strip(),
                "admin_level": form.get("admin_level", "none").strip(),
                "admin_scope_group_id": int(form["admin_scope_group_id"]) if form.get("admin_scope_group_id") else None,
            }
            api_call("PUT", f"/auth/users/{user_id}", json=payload)
            flash("User updated", "success")
        except Exception as exc:
            flash(f"Edit user error: {exc}", "danger")
        return redirect(url_for("admin_edit_user_page", user_id=user_id))

    @app.post("/admin/users/<int:user_id>/groups/add")
    @admin_panel_required
    def admin_user_add_group(user_id: int):
        try:
            group_id = int(request.form.get("group_id", "0"))
            api_call("POST", "/acl/groups/bind-user", json={"user_id": user_id, "group_id": group_id})
            flash("User added to group", "success")
        except Exception as exc:
            flash(f"Add group error: {exc}", "danger")
        return redirect(url_for("admin_edit_user_page", user_id=user_id))

    @app.post("/admin/users/<int:user_id>/groups/<int:group_id>/remove")
    @admin_panel_required
    def admin_user_remove_group(user_id: int, group_id: int):
        try:
            api_call("DELETE", f"/acl/groups/{group_id}/users/{user_id}")
            flash("User removed from group", "success")
        except Exception as exc:
            flash(f"Remove group error: {exc}", "danger")
        return redirect(url_for("admin_edit_user_page", user_id=user_id))

    @app.post("/admin/users/<int:user_id>/password")
    @admin_panel_required
    def admin_set_user_password(user_id: int):
        new_password = request.form.get("password", "").strip()
        try:
            if not new_password:
                raise RuntimeError("Password is required")
            api_call("POST", f"/auth/users/{user_id}/password", json={"password": new_password})
            flash("Password changed", "success")
        except Exception as exc:
            flash(f"Change password error: {exc}", "danger")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/toggle-block")
    @admin_panel_required
    def admin_toggle_user_block(user_id: int):
        blocked = request.form.get("is_blocked", "0") == "1"
        try:
            api_call("POST", f"/auth/users/{user_id}/{'unblock' if blocked else 'block'}")
            flash("User status updated", "success")
        except Exception as exc:
            flash(f"Toggle block error: {exc}", "danger")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/delete")
    @admin_panel_required
    def admin_delete_user(user_id: int):
        try:
            api_call("DELETE", f"/auth/users/{user_id}")
            flash("User deleted", "success")
        except Exception as exc:
            flash(f"Delete user error: {exc}", "danger")
        return redirect(url_for("admin_users"))

    @app.get("/admin/groups")
    @admin_panel_required
    def admin_groups():
        try:
            refresh_profile()
            data = admin_data()
            groups = data.get("groups", [])
            users = {u["id"]: u for u in data.get("users", [])}
            user_groups = data.get("user_groups", [])
            permissions = data.get("permissions", [])

            member_count = {g["id"]: 0 for g in groups}
            for ug in user_groups:
                gid = ug["group_id"]
                if gid in member_count and ug["user_id"] in users:
                    member_count[gid] += 1

            admin_codes = {"manage_users", "manage_groups", "manage_nodes", "manage_volumes", "manage_permissions", "admin_panel"}
            group_admin = {g["id"]: False for g in groups}
            for p in permissions:
                if p["permission_code"] in admin_codes and p["allow"] == 1:
                    group_admin[p["group_id"]] = True

            groups_view = [
                {
                    **g,
                    "users_count": member_count.get(g["id"], 0),
                    "is_admin_group": group_admin.get(g["id"], False) or "admin" in (g.get("group_type") or ""),
                }
                for g in groups
            ]
            groups_view.sort(key=lambda x: x["name"].lower())
            return render_template("admin_groups.html", groups=groups_view)
        except Exception as exc:
            flash(f"Groups page error: {exc}", "danger")
            return redirect(url_for("admin_dashboard"))

    @app.post("/admin/groups/create")
    @admin_panel_required
    def admin_create_group():
        form = request.form
        try:
            payload = {
                "name": form.get("name", "").strip(),
                "code": form.get("code", "").strip(),
                "group_type": form.get("group_type", "department").strip(),
                "parent_id": int(form["parent_id"]) if form.get("parent_id") else None,
            }
            api_call("POST", "/acl/groups", json=payload)
            flash("Group created", "success")
        except Exception as exc:
            flash(f"Create group error: {exc}", "danger")
        return redirect(url_for("admin_groups"))

    @app.post("/admin/groups/<int:group_id>/delete")
    @admin_panel_required
    def admin_delete_group(group_id: int):
        try:
            api_call("DELETE", f"/acl/groups/{group_id}")
            flash("Group deleted", "success")
        except Exception as exc:
            flash(f"Delete group error: {exc}", "danger")
        return redirect(url_for("admin_groups"))

    @app.get("/admin/groups/<int:group_id>")
    @admin_panel_required
    def admin_group_detail(group_id: int):
        try:
            refresh_profile()
            data = admin_data()
            groups = data.get("groups", [])
            users = data.get("users", [])
            resources = {r["id"]: r for r in data.get("resources", [])}
            permissions = data.get("permissions", [])
            user_groups = data.get("user_groups", [])

            group = next((g for g in groups if g["id"] == group_id), None)
            if not group:
                flash("Group not found", "danger")
                return redirect(url_for("admin_groups"))

            member_ids = {ug["user_id"] for ug in user_groups if ug["group_id"] == group_id}
            members = [u for u in users if u["id"] in member_ids]
            non_members = [u for u in users if u["id"] not in member_ids]

            group_permissions = [p for p in permissions if p["group_id"] == group_id]
            for p in group_permissions:
                p["resource_name"] = resources[p["resource_id"]]["name"] if p.get("resource_id") in resources else "Global"
                p["resource_path"] = resources[p["resource_id"]]["path"] if p.get("resource_id") in resources else "*"

            return render_template(
                "admin_group_detail.html",
                group=group,
                members=members,
                non_members=non_members,
                resources=list(resources.values()),
                permissions=group_permissions,
            )
        except Exception as exc:
            flash(f"Group detail error: {exc}", "danger")
            return redirect(url_for("admin_groups"))

    @app.post("/admin/groups/<int:group_id>/members/add")
    @admin_panel_required
    def admin_group_add_member(group_id: int):
        try:
            user_id = int(request.form.get("user_id", "0"))
            api_call("POST", "/acl/groups/bind-user", json={"user_id": user_id, "group_id": group_id})
            flash("User added to group", "success")
        except Exception as exc:
            flash(f"Add member error: {exc}", "danger")
        return redirect(url_for("admin_group_detail", group_id=group_id))

    @app.post("/admin/groups/<int:group_id>/members/<int:user_id>/remove")
    @admin_panel_required
    def admin_group_remove_member(group_id: int, user_id: int):
        try:
            api_call("DELETE", f"/acl/groups/{group_id}/users/{user_id}")
            flash("User removed from group", "success")
        except Exception as exc:
            flash(f"Remove member error: {exc}", "danger")
        return redirect(url_for("admin_group_detail", group_id=group_id))

    @app.post("/admin/groups/<int:group_id>/permissions/add")
    @admin_panel_required
    def admin_group_add_permission(group_id: int):
        try:
            payload = {
                "group_id": group_id,
                "resource_id": int(request.form["resource_id"]) if request.form.get("resource_id") else None,
                "permission_code": request.form.get("permission_code", "").strip(),
                "allow": request.form.get("allow", "1") == "1",
            }
            api_call("POST", "/acl/permissions/grant", json=payload)
            flash("Permission saved", "success")
        except Exception as exc:
            flash(f"Add permission error: {exc}", "danger")
        return redirect(url_for("admin_group_detail", group_id=group_id))

    @app.post("/admin/groups/<int:group_id>/permissions/<int:permission_id>/remove")
    @admin_panel_required
    def admin_group_remove_permission(group_id: int, permission_id: int):
        try:
            api_call("DELETE", f"/acl/permissions/{permission_id}")
            flash("Permission removed", "success")
        except Exception as exc:
            flash(f"Remove permission error: {exc}", "danger")
        return redirect(url_for("admin_group_detail", group_id=group_id))

    @app.get("/admin/resources")
    @admin_panel_required
    def admin_resources():
        try:
            refresh_profile()
            data = admin_data()
            nodes = data.get("nodes", [])
            resource_nodes = data.get("resource_nodes", [])
            resource_node_map: dict[int, list[int]] = {}
            for row in resource_nodes:
                rid = int(row.get("resource_id", 0))
                nid = int(row.get("node_id", 0))
                if rid <= 0 or nid <= 0:
                    continue
                resource_node_map.setdefault(rid, []).append(nid)
            return render_template(
                "admin_resources.html",
                resources=data.get("resources", []),
                nodes=nodes,
                resource_node_map=resource_node_map,
            )
        except Exception as exc:
            flash(f"Resources page error: {exc}", "danger")
            return redirect(url_for("admin_dashboard"))

    @app.post("/admin/resources/create")
    @admin_panel_required
    def admin_create_resource():
        form = request.form
        try:
            payload = {
                "name": form.get("name", "").strip(),
                "code": form.get("code", "").strip(),
                "path": form.get("path", "").strip(),
                "resource_type": form.get("resource_type", "folder").strip() or "folder",
                "size_limit_mb": int(form.get("size_limit_mb", "0") or 0),
                "parent_id": int(form["parent_id"]) if form.get("parent_id") else None,
                "is_hidden": bool(form.get("is_hidden")),
            }
            created = api_call("POST", "/acl/resources", json=payload)
            node_ids = [int(v) for v in form.getlist("node_ids") if str(v).strip()]
            if node_ids:
                api_call("PUT", f"/acl/resources/{int(created['id'])}/nodes", json={"node_ids": node_ids})
            flash("Resource created", "success")
        except Exception as exc:
            flash(f"Create resource error: {exc}", "danger")
        return redirect(url_for("admin_resources"))

    @app.post("/admin/resources/<int:resource_id>/delete")
    @admin_panel_required
    def admin_delete_resource(resource_id: int):
        try:
            api_call("DELETE", f"/acl/resources/{resource_id}")
            flash("Resource deleted", "success")
        except Exception as exc:
            flash(f"Delete resource error: {exc}", "danger")
        return redirect(url_for("admin_resources"))

    @app.post("/admin/resources/<int:resource_id>/limit")
    @admin_panel_required
    def admin_update_resource_limit(resource_id: int):
        try:
            size_limit_mb = int(request.form.get("size_limit_mb", "0") or 0)
            api_call("PUT", f"/acl/resources/{resource_id}", json={"size_limit_mb": size_limit_mb})
            flash("Resource limit updated", "success")
        except Exception as exc:
            flash(f"Update resource limit error: {exc}", "danger")
        return redirect(url_for("admin_resources"))

    @app.post("/admin/resources/<int:resource_id>/nodes")
    @admin_panel_required
    def admin_update_resource_nodes(resource_id: int):
        try:
            node_ids = [int(v) for v in request.form.getlist("node_ids") if str(v).strip()]
            api_call("PUT", f"/acl/resources/{resource_id}/nodes", json={"node_ids": node_ids})
            flash("Resource nodes updated", "success")
        except Exception as exc:
            flash(f"Update resource nodes error: {exc}", "danger")
        return redirect(url_for("admin_resources"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
