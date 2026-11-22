import json
import os
import urllib.error
import urllib.parse
import urllib.request


class SupabaseAuthError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _settings() -> tuple[str, str]:
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = (
        os.environ.get("SUPABASE_ANON_KEY")
        or os.environ.get("SUPABASE_PUBLISHABLE_KEY")
        or ""
    ).strip()
    return url, key


def is_configured() -> bool:
    url, key = _settings()
    return bool(url and key)


def _admin_settings() -> tuple[str, str]:
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = (
        os.environ.get("SUPABASE_SECRET_KEY")
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or ""
    ).strip()
    return url, key


def is_admin_configured() -> bool:
    url, key = _admin_settings()
    return bool(url and key)


def _base_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise SupabaseAuthError("SUPABASE_URL must be an http(s) URL", 503)
    return f"{parsed.scheme}://{parsed.netloc}"


def _request(method: str, path: str, body: dict | None = None,
             access_token: str | None = None) -> dict:
    url, key = _settings()
    if not url or not key:
        raise SupabaseAuthError("Supabase Auth is not configured", 503)
    request = urllib.request.Request(
        _base_url(url) + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "apikey": key,
            "Authorization": f"Bearer {access_token or key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}
        message = (
            payload.get("msg")
            or payload.get("message")
            or payload.get("error_description")
            or exc.reason
            or "Supabase Auth request failed"
        )
        status = exc.code if exc.code in (400, 401, 409, 422) else 502
        raise SupabaseAuthError(str(message), status) from exc
    except urllib.error.URLError as exc:
        raise SupabaseAuthError("Could not reach Supabase Auth", 502) from exc
    except json.JSONDecodeError as exc:
        raise SupabaseAuthError("Supabase Auth returned invalid JSON", 502) from exc


def _admin_request(method: str, path: str, body: dict | None = None) -> dict:
    url, key = _admin_settings()
    if not url or not key:
        raise SupabaseAuthError("Supabase admin API is not configured", 503)
    request = urllib.request.Request(
        _base_url(url) + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}
        message = (
            payload.get("msg")
            or payload.get("message")
            or payload.get("error_description")
            or exc.reason
            or "Supabase admin request failed"
        )
        status = exc.code if exc.code in (400, 401, 409, 422) else 502
        raise SupabaseAuthError(str(message), status) from exc
    except urllib.error.URLError as exc:
        raise SupabaseAuthError("Could not reach Supabase Auth", 502) from exc
    except json.JSONDecodeError as exc:
        raise SupabaseAuthError("Supabase Auth returned invalid JSON", 502) from exc


def admin_create_user(email: str, password: str, user_metadata: dict,
                      app_metadata: dict) -> dict:
    return _admin_request("POST", "/auth/v1/admin/users", {
        "email": email,
        "password": password,
        "email_confirm": True,
        "user_metadata": user_metadata,
        "app_metadata": app_metadata,
    })


def sign_up(email: str, password: str, metadata: dict) -> dict:
    return _request("POST", "/auth/v1/signup", {
        "email": email,
        "password": password,
        "data": metadata,
    })


def sign_in(email: str, password: str) -> dict:
    return _request("POST", "/auth/v1/token?grant_type=password", {
        "email": email,
        "password": password,
    })


def recover(email: str) -> dict:
    return _request("POST", "/auth/v1/recover", {"email": email})


def update_password(access_token: str, password: str) -> dict:
    return _request("PUT", "/auth/v1/user", {"password": password},
                    access_token=access_token)


def get_user(access_token: str) -> dict:
    return _request("GET", "/auth/v1/user", access_token=access_token)


def access_token(payload: dict) -> str | None:
    session = payload.get("session") or {}
    return payload.get("access_token") or session.get("access_token")


def auth_user(payload: dict) -> dict:
    session = payload.get("session") or {}
    return payload.get("user") or session.get("user") or {}


def admin_user(payload: dict) -> dict:
    return payload.get("user") or payload
