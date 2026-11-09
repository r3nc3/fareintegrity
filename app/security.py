import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

ALGORITHM = "HS256"
SECRET = os.environ.get(
    "FAREGUARD_SECRET",
    "dev-secret-change-me-fareguard-integrity-platform-0001",
)
TOKEN_TTL = timedelta(hours=12)

ROLE_PLATFORM = "PLATFORM_ADMIN"
ROLE_SACCO = "SACCO_ADMIN"
ROLE_CONDUCTOR = "CONDUCTOR"
ROLE_AUDITOR = "AUDITOR"

_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = hashlib.sha256(secrets.token_bytes(24)).hexdigest()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _ITERATIONS)
    return f"pbkdf2${_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, hex_digest = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(digest.hex(), hex_digest)
    except Exception:
        return False


def make_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "tenant_id": user.tenant_id,
        "exp": (datetime.now(timezone.utc) + TOKEN_TTL).timestamp(),
    }
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


bearer = HTTPBearer(auto_error=False)


def current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.active:
        raise HTTPException(401, "Unknown or inactive user")
    return user


def require_roles(*roles):
    def dep(user: User = Depends(current_user)):
        if user.role not in roles:
            raise HTTPException(403, "Insufficient permissions")
        return user

    return dep


def ensure_tenant(user: User, tenant_id: int | None) -> None:
    if user.role == ROLE_PLATFORM:
        return
    if tenant_id is None or user.tenant_id != tenant_id:
        raise HTTPException(403, "Cross-tenant access denied")
