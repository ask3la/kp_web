from fastapi import Request


def client_ip(request: Request) -> str | None:
    x_forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
    if x_forwarded_for:
        return x_forwarded_for.split(",", 1)[0].strip() or None
    x_real_ip = (request.headers.get("x-real-ip") or "").strip()
    if x_real_ip:
        return x_real_ip
    return request.client.host if request.client else None


def client_user_agent(request: Request) -> str | None:
    ua = (request.headers.get("x-original-user-agent") or request.headers.get("user-agent") or "").strip()
    return ua or None
