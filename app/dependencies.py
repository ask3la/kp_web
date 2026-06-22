from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .request_meta import client_ip
from .repositories import AuditLogRepository, UserRepository
from .security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)
audit = AuditLogRepository()


def _log_unauthorized(request: Request, reason: str) -> None:
    try:
        audit.create(
            event_code="unauthorized_access",
            message="Anonymous access denied",
            user_id=None,
            username="anonymous",
            ip_address=client_ip(request),
            actor_type="anonymous",
            meta={"path": str(request.url.path), "method": request.method, "reason": reason},
        )
    except Exception:
        pass


def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    if not credentials:
        _log_unauthorized(request, "missing_credentials")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization required")
    try:
        payload = decode_access_token(credentials.credentials)
    except HTTPException:
        _log_unauthorized(request, "invalid_token")
        raise
    user = UserRepository().get_by_id(int(payload["sub"]))
    if not user:
        _log_unauthorized(request, "user_not_found")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if bool(user.get("is_blocked")):
        _log_unauthorized(request, "blocked_user")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def require_employee_or_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] not in ("admin", "employee"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Employee or admin access required")
    return user


def require_super_admin(user: dict = Depends(require_admin)) -> dict:
    if user["admin_level"] != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Super admin access required")
    return user
