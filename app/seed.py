from .repositories import GroupRepository, PermissionRepository, ResourceRepository, UserGroupRepository, UserRepository
from .security import hash_password


def _ensure_user(users: UserRepository, username: str, password: str, role: str, admin_level: str = "none", scope: int | None = None) -> dict:
    existing = users.get_by_username(username)
    if existing:
        if existing["admin_level"] != admin_level or existing["admin_scope_group_id"] != scope:
            users.update_admin_attrs(existing["id"], admin_level, scope)
            existing = users.get_by_id(existing["id"])
        return existing
    return users.create(
        username=username,
        password_hash=hash_password(password),
        role=role,
        admin_level=admin_level,
        admin_scope_group_id=scope,
    )


def _ensure_group(groups: GroupRepository, code: str, name: str, group_type: str, parent_id: int | None = None) -> dict:
    for g in groups.list_groups():
        if g["code"] == code:
            return g
    return groups.create(name=name, code=code, group_type=group_type, parent_id=parent_id)


def _ensure_resource(resources: ResourceRepository, code: str, name: str, path: str, resource_type: str, parent_id: int | None = None) -> dict:
    for r in resources.list_resources():
        if r["code"] == code:
            return r
    return resources.create(
        {
            "name": name,
            "code": code,
            "path": path,
            "resource_type": resource_type,
            "parent_id": parent_id,
            "is_hidden": False,
        }
    )


def seed_if_empty() -> None:
    users = UserRepository()
    groups = GroupRepository()
    user_groups = UserGroupRepository()
    resources = ResourceRepository()
    perms = PermissionRepository()

    root_group = _ensure_group(groups, "admins.root", "Главные администраторы", "admin_root")
    dep_group = _ensure_group(groups, "dep.engineering", "Отдел разработки", "department")
    client_group = _ensure_group(groups, "client.acme", "Клиент Acme", "client")

    root_res = _ensure_resource(resources, "root", "Корень облака", "/", "folder")
    shared_res = _ensure_resource(resources, "shared.docs", "Общие документы", "/shared/docs", "folder", parent_id=root_res["id"])
    client_res = _ensure_resource(resources, "client.acme.data", "Ресурс клиента Acme", "/clients/acme", "folder", parent_id=root_res["id"])

    admin = _ensure_user(users, "admin", "admin123", "admin", admin_level="super_admin")
    org_admin = _ensure_user(users, "orgadmin", "orgadmin123", "admin", admin_level="org_admin", scope=dep_group["id"])
    employee = _ensure_user(users, "employee1", "employee123", "employee")
    client = _ensure_user(users, "client1", "client123", "client")

    user_groups.bind(admin["id"], root_group["id"])
    user_groups.bind(org_admin["id"], dep_group["id"])
    user_groups.bind(employee["id"], dep_group["id"])
    user_groups.bind(client["id"], client_group["id"])

    employee_personal = _ensure_resource(
        resources,
        f"user.{employee['id']}.personal",
        f"Личное облако {employee['username']}",
        f"/users/{employee['username']}",
        "folder",
        parent_id=root_res["id"],
    )
    client_personal = _ensure_resource(
        resources,
        f"user.{client['id']}.personal",
        f"Личное облако {client['username']}",
        f"/users/{client['username']}",
        "folder",
        parent_id=root_res["id"],
    )

    employee_personal_group = _ensure_group(groups, f"user.{employee['id']}.group", f"Группа {employee['username']}", "personal")
    client_personal_group = _ensure_group(groups, f"user.{client['id']}.group", f"Группа {client['username']}", "personal")
    user_groups.bind(employee["id"], employee_personal_group["id"])
    user_groups.bind(client["id"], client_personal_group["id"])

    for code in ("view", "read", "write", "delete", "manage_users", "manage_groups", "manage_nodes", "manage_volumes", "manage_permissions", "admin_panel"):
        perms.grant(root_group["id"], None, code, True)

    for code in ("view", "read", "write"):
        perms.grant(dep_group["id"], shared_res["id"], code, True)
    for code in ("manage_users", "manage_groups", "admin_panel"):
        perms.grant(dep_group["id"], None, code, True)

    for code in ("view", "read", "write", "delete"):
        perms.grant(employee_personal_group["id"], employee_personal["id"], code, True)
        perms.grant(client_personal_group["id"], client_personal["id"], code, True)
    for code in ("view", "read", "write"):
        perms.grant(client_group["id"], client_res["id"], code, True)
