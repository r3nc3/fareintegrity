import csv
import io
import json
import re
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from . import integrity
from .audit import log_audit, verify_chain
from .db import Base, engine, get_db
from .models import (
    AuditLog,
    DailyTarget,
    FareTransaction,
    IngestBatch,
    IntegrityFlag,
    ReconciliationRun,
    Route,
    Shift,
    Stage,
    Tenant,
    User,
    Vehicle,
    utcnow,
)
from .security import (
    ROLE_AUDITOR,
    ROLE_CONDUCTOR,
    ROLE_PLATFORM,
    ROLE_SACCO,
    current_user,
    ensure_tenant,
    hash_password,
    make_token,
    require_roles,
    verify_password,
)
from .seed import seed as seed_db
from .services import reconciliation
from . import supabase_auth
from .supabase_auth import SupabaseAuthError

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT / "dashboard"


def _ensure_target_schema():
    timestamp_type = "TIMESTAMP" if engine.dialect.name == "postgresql" else "DATETIME"
    with engine.connect() as conn:
        daily_columns = {
            column["name"] for column in inspect(conn).get_columns("daily_targets")
        }
        for name, ddl in (
            ("declared_cents", "INTEGER"),
            ("declared_by", "INTEGER"),
            ("declared_at", timestamp_type),
        ):
            if name not in daily_columns:
                conn.execute(text(f"ALTER TABLE daily_targets ADD COLUMN {name} {ddl}"))
        vehicle_columns = {
            column["name"] for column in inspect(conn).get_columns("vehicles")
        }
        for name, ddl in (
            ("daily_target_cents", "INTEGER"),
            ("target_updated_at", timestamp_type),
            ("target_updated_by", "INTEGER"),
        ):
            if name not in vehicle_columns:
                conn.execute(text(f"ALTER TABLE vehicles ADD COLUMN {name} {ddl}"))
        user_columns = {
            column["name"] for column in inspect(conn).get_columns("users")
        }
        if "supabase_user_id" not in user_columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN supabase_user_id VARCHAR(64)"))
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_supabase_id "
            "ON users (supabase_user_id) WHERE supabase_user_id IS NOT NULL"
        ))
        conn.commit()

    with Session(engine) as db:
        vehicles = (
            db.query(Vehicle)
            .filter(Vehicle.daily_target_cents.is_(None))
            .all()
        )
        for vehicle in vehicles:
            latest = (
                db.query(DailyTarget)
                .filter(
                    DailyTarget.tenant_id == vehicle.tenant_id,
                    DailyTarget.vehicle_id == vehicle.id,
                )
                .order_by(DailyTarget.day.desc(), DailyTarget.id.desc())
                .first()
            )
            if latest is not None:
                vehicle.daily_target_cents = latest.target_cents
                vehicle.target_updated_at = latest.created_at or utcnow()
                vehicle.target_updated_by = latest.created_by
        db.commit()


def initialize_database():
    Base.metadata.create_all(bind=engine)
    _ensure_target_schema()
    with Session(engine) as db:
        seed_db(db)


@asynccontextmanager
async def lifespan(app):
    initialize_database()
    yield


app = FastAPI(title="FareGuard", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

READ_ROLES = (ROLE_PLATFORM, ROLE_SACCO, ROLE_CONDUCTOR, ROLE_AUDITOR)
MANAGE_ROLES = (ROLE_PLATFORM, ROLE_SACCO)


# ---------- helpers ----------

def _tx_json(t: FareTransaction) -> dict:
    return {
        "id": t.id,
        "tenant_id": t.tenant_id,
        "source": t.source,
        "external_ref": t.external_ref,
        "device_id": t.device_id,
        "device_seq": t.device_seq,
        "provider_receipt": t.provider_receipt,
        "vehicle_id": t.vehicle_id,
        "route_id": t.route_id,
        "stage_id": t.stage_id,
        "shift_id": t.shift_id,
        "conductor_id": t.conductor_id,
        "passenger_count": t.passenger_count,
        "amount_cents": t.amount_cents,
        "amount_kes": t.amount_cents / 100,
        "method": t.method,
        "occurred_at": t.occurred_at.isoformat() if t.occurred_at else None,
        "received_at": t.received_at.isoformat() if t.received_at else None,
        "status": t.status,
        "integrity_status": t.integrity_status,
        "idempotency_key": t.idempotency_key,
        "fingerprint": t.fingerprint[:16],
        "reversal_reason": t.reversal_reason,
        "reversed_at": t.reversed_at.isoformat() if t.reversed_at else None,
    }


_CENTS_TEXT = re.compile(r"(\d+) cents")
_STAGE_FARE_TEXT = re.compile(r"\((\d+) x (\d+)\)")


def _flag_detail(detail: str | None) -> str | None:
    if not detail:
        return detail
    detail = _CENTS_TEXT.sub(
        lambda m: f"KES {int(m.group(1)) / 100:,.2f}", detail)
    return _STAGE_FARE_TEXT.sub(
        lambda m: f"({m.group(1)} x KES {int(m.group(2)) / 100:,.2f})", detail)


def _flag_json(f: IntegrityFlag) -> dict:
    return {
        "id": f.id,
        "tenant_id": f.tenant_id,
        "kind": f.kind,
        "severity": f.severity,
        "transaction_id": f.transaction_id,
        "shift_id": f.shift_id,
        "device_id": f.device_id,
        "vehicle_id": f.vehicle_id,
        "sequence_no": f.sequence_no,
        "detail": _flag_detail(f.detail),
        "status": f.status,
        "detected_at": f.detected_at.isoformat() if f.detected_at else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "resolution_note": f.resolution_note,
    }


def _scope(user: User, tenant_id: int | None):
    """Read scope. Platform admin may pass None to see all tenants."""
    if user.role == ROLE_PLATFORM:
        return tenant_id
    ensure_tenant(user, tenant_id or user.tenant_id)
    return user.tenant_id


def _require_tenant(user: User, tenant_id: int | None) -> int:
    if user.role == ROLE_PLATFORM:
        if tenant_id is None:
            raise HTTPException(422, "tenant_id is required for platform operators")
        return tenant_id
    ensure_tenant(user, tenant_id or user.tenant_id)
    return user.tenant_id


def _flag_summary(db: Session, tenant_id: int | None) -> dict:
    query = db.query(IntegrityFlag)
    if tenant_id is not None:
        query = query.filter(IntegrityFlag.tenant_id == tenant_id)
    flags = query.all()
    open_flags = [f for f in flags if f.status in ("OPEN", "INVESTIGATING")]
    by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_kind: dict[str, int] = {}
    for flag in open_flags:
        by_severity[flag.severity] = by_severity.get(flag.severity, 0) + 1
        by_kind[flag.kind] = by_kind.get(flag.kind, 0) + 1
    return {
        "open": len(open_flags),
        "by_severity": by_severity,
        "by_kind": by_kind,
    }


@app.exception_handler(integrity.IntegrityViolation)
def integrity_exception_handler(request, exc: integrity.IntegrityViolation):
    content = {"error": exc.code, "detail": str(exc)}
    if isinstance(exc, integrity.DuplicateTransaction) and exc.existing is not None:
        content["existing"] = _tx_json(exc.existing)
    return JSONResponse(status_code=exc.status_code, content=content)


# ---------- auth ----------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class LoginBody(BaseModel):
    email: str = Field(..., max_length=150)
    password: str = Field(..., max_length=200)


class SignupBody(BaseModel):
    email: str = Field(..., max_length=150)
    password: str = Field(..., min_length=8, max_length=200)
    full_name: str = Field(..., min_length=2, max_length=150)
    sacco_name: str = Field(..., min_length=2, max_length=200)


def _normalise_email(email: str) -> str:
    value = email.strip().lower()
    if not _EMAIL_RE.fullmatch(value):
        raise HTTPException(422, "Enter a valid email address")
    return value


def _text(value, limit: int, fallback: str) -> str:
    cleaned = str(value or "").strip()
    return cleaned[:limit] if cleaned else fallback


def _supabase_error(error: SupabaseAuthError) -> HTTPException:
    message = error.message.lower()
    if "not confirmed" in message or "confirm" in message:
        return HTTPException(403, "Confirm your email address before signing in")
    if "already registered" in message or "already exists" in message:
        return HTTPException(409, "An account with that email already exists")
    if "invalid" in message:
        return HTTPException(401, "Invalid credentials")
    if "password" in message and error.status_code in (400, 422):
        return HTTPException(422, error.message)
    return HTTPException(error.status_code, error.message)


def _sync_supabase_user(db: Session, remote: dict, action: str) -> User:
    remote_id = str(remote.get("id") or "").strip()
    email = _normalise_email(str(remote.get("email") or ""))
    if not remote_id:
        raise HTTPException(502, "Supabase Auth returned an invalid user")

    metadata = remote.get("user_metadata") or {}
    user = db.query(User).filter(User.supabase_user_id == remote_id).first()
    created = False

    if user is None:
        user = db.query(User).filter(User.email == email).first()
        if user is not None:
            raise HTTPException(
                409,
                "That email is already registered. Sign in with its existing password.",
            )
        else:
            domain = email.rsplit("@", 1)[-1].split(".")[0].replace("-", " ").title()
            sacco_name = _text(metadata.get("sacco_name"), 200, f"{domain} SACCO")
            full_name = _text(metadata.get("full_name"), 150, email.split("@", 1)[0])
            tenant = Tenant(
                name=sacco_name,
                contact_email=email,
                subscription_active=True,
            )
            db.add(tenant)
            db.flush()
            user = User(
                tenant_id=tenant.id,
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(32)),
                full_name=full_name,
                role=ROLE_SACCO,
                active=True,
                supabase_user_id=remote_id,
            )
            db.add(user)
            db.flush()
            created = True

    if user.email != email:
        conflict = db.query(User).filter(User.email == email).first()
        if conflict is not None and conflict.id != user.id:
            raise HTTPException(409, "That email is already in use")
        user.email = email
    if not user.active:
        raise HTTPException(403, "Account disabled")

    log_audit(
        db, tenant_id=user.tenant_id, actor_id=user.id, actor_email=user.email,
        action=action, entity="user", entity_id=user.id,
        summary="Supabase account linked" if created else "Supabase sign-in success",
    )
    db.commit()
    return user


def _auth_payload(db: Session, user: User) -> dict:
    tenant = db.get(Tenant, user.tenant_id) if user.tenant_id else None
    return {
        "token": make_token(user),
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "tenant_id": user.tenant_id,
            "tenant_name": tenant.name if tenant else None,
        },
    }


def _local_login(db: Session, email: str, password: str) -> dict:
    user = db.query(User).filter(User.email == email).first()
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    if not user.active:
        raise HTTPException(403, "Account disabled")
    log_audit(
        db, tenant_id=user.tenant_id, actor_id=user.id, actor_email=user.email,
        action="LOGIN", entity="user", entity_id=user.id, summary="login success",
    )
    db.commit()
    return _auth_payload(db, user)


@app.get("/api/auth/config")
def auth_config():
    return {"supabase_enabled": supabase_auth.is_configured()}


@app.post("/api/auth/signup")
def signup(body: SignupBody, db: Session = Depends(get_db)):
    if not supabase_auth.is_configured():
        raise HTTPException(503, "Supabase Auth is not configured")
    email = _normalise_email(body.email)
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(409, "An account with that email already exists")
    try:
        result = supabase_auth.sign_up(email, body.password, {
            "full_name": body.full_name.strip(),
            "sacco_name": body.sacco_name.strip(),
            "signup_source": "fareguard_dashboard",
        })
    except SupabaseAuthError as error:
        raise _supabase_error(error)

    token = supabase_auth.access_token(result)
    if not token:
        return {
            "needs_confirmation": True,
            "message": "Check your email to confirm your address, then sign in.",
        }
    try:
        remote = supabase_auth.get_user(token)
        user = _sync_supabase_user(db, remote, "SUPABASE_SIGNUP")
    except SupabaseAuthError as error:
        raise _supabase_error(error)
    return _auth_payload(db, user)


@app.post("/api/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    email = _normalise_email(body.email)
    if supabase_auth.is_configured():
        try:
            result = supabase_auth.sign_in(email, body.password)
            token = supabase_auth.access_token(result)
            if not token:
                raise SupabaseAuthError("Supabase Auth did not return a session", 401)
            remote = supabase_auth.get_user(token)
            user = _sync_supabase_user(db, remote, "SUPABASE_LOGIN")
            return _auth_payload(db, user)
        except SupabaseAuthError as error:
            message = error.message.lower()
            if "confirm" not in message:
                if db.query(User).filter(
                    User.email == email, User.supabase_user_id.isnot(None)
                ).first() is not None:
                    raise _supabase_error(error)
                try:
                    return _local_login(db, email, body.password)
                except HTTPException:
                    raise _supabase_error(error)
            raise _supabase_error(error)
    return _local_login(db, email, body.password)


@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {
        "id": user.id, "email": user.email, "role": user.role,
        "tenant_id": user.tenant_id, "full_name": user.full_name,
    }


# ---------- masters ----------

@app.get("/api/tenants")
def list_tenants(user: User = Depends(require_roles(ROLE_PLATFORM)),
                 db: Session = Depends(get_db)):
    return [
        {"id": t.id, "name": t.name, "region": t.region,
         "subscription_active": t.subscription_active}
        for t in db.query(Tenant).all()
    ]


@app.get("/api/saccos/")
def list_saccos(user: User = Depends(require_roles(ROLE_PLATFORM)),
                db: Session = Depends(get_db)):
    return list_tenants(user=user, db=db)


@app.get("/api/vehicles")
def list_vehicles(tenant_id: int | None = Query(None),
                  db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(Vehicle)
    if tid is not None:
        query = query.filter(Vehicle.tenant_id == tid)
    return [_vehicle_json(v) for v in query.all()]


@app.get("/api/routes")
def list_routes(tenant_id: int | None = Query(None),
                db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(Route)
    if tid is not None:
        query = query.filter(Route.tenant_id == tid)
    out = []
    for route in query.all():
        stages = (
            db.query(Stage).filter(Stage.route_id == route.id)
            .order_by(Stage.order).all()
        )
        out.append({
            "id": route.id, "name": route.name, "tenant_id": route.tenant_id,
            "active": route.active,
            "stages": [
                {"id": s.id, "name": s.name, "order": s.order,
                 "fare_cents": s.fare_cents, "fare_kes": s.fare_cents / 100}
                for s in stages
            ],
        })
    return out


# ---------- administration: tenants, users, fleet, routes ----------

VALID_ROLES = (ROLE_PLATFORM, ROLE_SACCO, ROLE_CONDUCTOR, ROLE_AUDITOR)
SACCO_ASSIGNABLE_ROLES = (ROLE_CONDUCTOR, ROLE_AUDITOR)


def _user_json(u: User, tenant_name: str | None = None) -> dict:
    return {
        "id": u.id, "tenant_id": u.tenant_id, "email": u.email,
        "full_name": u.full_name, "role": u.role, "active": u.active,
        "tenant_name": tenant_name,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def _vehicle_json(v: Vehicle) -> dict:
    return {
        "id": v.id, "tenant_id": v.tenant_id, "reg_no": v.reg_no,
        "capacity": v.capacity, "device_id": v.device_id, "active": v.active,
        "daily_target_cents": v.daily_target_cents,
        "daily_target_kes": (
            v.daily_target_cents / 100
            if v.daily_target_cents is not None else None
        ),
        "target_updated_at": (
            v.target_updated_at.isoformat() if v.target_updated_at else None
        ),
    }


def _route_json(db: Session, route: Route) -> dict:
    stages = (
        db.query(Stage).filter(Stage.route_id == route.id)
        .order_by(Stage.order).all()
    )
    return {
        "id": route.id, "name": route.name, "tenant_id": route.tenant_id,
        "active": route.active,
        "stages": [
            {"id": s.id, "name": s.name, "order": s.order,
             "fare_cents": s.fare_cents, "fare_kes": s.fare_cents / 100}
            for s in stages
        ],
    }


def _target_user(db: Session, actor: User, user_id: int) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if actor.role == ROLE_PLATFORM:
        return target
    if target.tenant_id != actor.tenant_id or target.role == ROLE_PLATFORM:
        raise HTTPException(403, "Cross-tenant access denied")
    return target


def _target_vehicle(db: Session, actor: User, vehicle_id: int) -> Vehicle:
    vehicle = db.get(Vehicle, vehicle_id)
    if vehicle is None:
        raise HTTPException(404, "Vehicle not found")
    ensure_tenant(actor, vehicle.tenant_id)
    return vehicle


def _target_route(db: Session, actor: User, route_id: int) -> Route:
    route = db.get(Route, route_id)
    if route is None:
        raise HTTPException(404, "Route not found")
    ensure_tenant(actor, route.tenant_id)
    return route


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    region: str | None = Field(default=None, max_length=120)
    contact_email: str | None = Field(default=None, max_length=150)


@app.post("/api/tenants")
def create_tenant(body: TenantCreate, db: Session = Depends(get_db),
                  user: User = Depends(require_roles(ROLE_PLATFORM))):
    name = body.name.strip()
    if db.query(Tenant).filter(Tenant.name == name).first():
        raise HTTPException(409, "A SACCO with that name already exists")
    tenant = Tenant(
        name=name,
        region=(body.region or "").strip() or None,
        contact_email=(body.contact_email or "").strip() or None,
    )
    db.add(tenant)
    db.flush()
    log_audit(db, tenant_id=tenant.id, actor_id=user.id, actor_email=user.email,
              action="TENANT_CREATED", entity="tenant", entity_id=tenant.id,
              summary=f"SACCO created: {tenant.name}")
    db.commit()
    return {"id": tenant.id, "name": tenant.name, "region": tenant.region,
            "contact_email": tenant.contact_email,
            "subscription_active": tenant.subscription_active}


class UserCreate(BaseModel):
    tenant_id: int | None = None
    email: str = Field(min_length=3, max_length=150)
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=150)
    role: str


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=150)
    password: str | None = Field(default=None, min_length=8, max_length=128)
    role: str | None = None
    active: bool | None = None


@app.get("/api/users")
def list_users(tenant_id: int | None = Query(None),
               db: Session = Depends(get_db),
               user: User = Depends(require_roles(*MANAGE_ROLES))):
    tid = _scope(user, tenant_id)
    query = db.query(User)
    if tid is not None:
        query = query.filter(User.tenant_id == tid)
    tenants = {t.id: t.name for t in db.query(Tenant).all()}
    return [_user_json(u, tenants.get(u.tenant_id))
            for u in query.order_by(User.id).all()]


@app.post("/api/users")
def create_user(body: UserCreate, db: Session = Depends(get_db),
                user: User = Depends(require_roles(*MANAGE_ROLES))):
    role = body.role.strip().upper()
    if role not in VALID_ROLES:
        raise HTTPException(422, f"role must be one of {', '.join(VALID_ROLES)}")
    email = body.email.strip().lower()
    if "@" not in email:
        raise HTTPException(422, "invalid email address")

    if user.role == ROLE_PLATFORM:
        tenant_id = body.tenant_id
        if role == ROLE_PLATFORM:
            tenant_id = None
        elif tenant_id is None:
            raise HTTPException(422, "tenant_id is required for non-platform users")
        elif db.get(Tenant, tenant_id) is None:
            raise HTTPException(404, "Tenant not found")
    else:
        if role not in SACCO_ASSIGNABLE_ROLES:
            raise HTTPException(
                403, "SACCO admins may only create conductors and auditors")
        tenant_id = user.tenant_id

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Email is already registered")

    new_user = User(tenant_id=tenant_id, email=email,
                    password_hash=hash_password(body.password),
                    full_name=body.full_name.strip(), role=role)
    db.add(new_user)
    db.flush()
    log_audit(db, tenant_id=tenant_id, actor_id=user.id, actor_email=user.email,
              action="USER_CREATED", entity="user", entity_id=new_user.id,
              summary=f"{role} created: {email}")
    db.commit()
    tenant = db.get(Tenant, tenant_id) if tenant_id else None
    return _user_json(new_user, tenant.name if tenant else None)


@app.patch("/api/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db),
                actor: User = Depends(require_roles(*MANAGE_ROLES))):
    target = _target_user(db, actor, user_id)
    if (actor.role == ROLE_SACCO and target.id != actor.id
            and target.role not in SACCO_ASSIGNABLE_ROLES):
        raise HTTPException(
            403, "SACCO admins may only manage conductors and auditors")
    if body.role is not None:
        role = body.role.strip().upper()
        if role not in VALID_ROLES:
            raise HTTPException(422, "invalid role")
        if (role == ROLE_PLATFORM) != (target.role == ROLE_PLATFORM):
            raise HTTPException(
                422, "platform-admin role cannot be changed; create a new user")
        if actor.role == ROLE_SACCO and role not in SACCO_ASSIGNABLE_ROLES:
            raise HTTPException(
                403, "SACCO admins may only assign conductor or auditor roles")
        target.role = role
    if body.full_name is not None:
        target.full_name = body.full_name.strip()
    if body.password is not None:
        target.password_hash = hash_password(body.password)
    if body.active is not None:
        if target.id == actor.id and not body.active:
            raise HTTPException(422, "You cannot deactivate your own account")
        target.active = body.active
    log_audit(db, tenant_id=target.tenant_id, actor_id=actor.id,
              actor_email=actor.email, action="USER_UPDATED", entity="user",
              entity_id=target.id, summary=f"User updated: {target.email}")
    db.commit()
    tenant = db.get(Tenant, target.tenant_id) if target.tenant_id else None
    return _user_json(target, tenant.name if tenant else None)


class VehicleCreate(BaseModel):
    tenant_id: int | None = None
    reg_no: str = Field(min_length=2, max_length=40)
    capacity: int = Field(default=14, ge=1, le=100)
    device_id: str | None = Field(default=None, max_length=80)
    active: bool = True


class VehicleUpdate(BaseModel):
    reg_no: str | None = Field(default=None, min_length=2, max_length=40)
    capacity: int | None = Field(default=None, ge=1, le=100)
    device_id: str | None = Field(default=None, max_length=80)
    active: bool | None = None


def _check_vehicle_unique(db: Session, tenant_id: int, reg_no: str,
                          device_id: str | None,
                          exclude_id: int | None = None) -> None:
    query = db.query(Vehicle).filter(
        Vehicle.tenant_id == tenant_id, Vehicle.reg_no == reg_no)
    if exclude_id is not None:
        query = query.filter(Vehicle.id != exclude_id)
    if query.first():
        raise HTTPException(409, "A vehicle with that registration already exists")
    if device_id:
        query = db.query(Vehicle).filter(
            Vehicle.tenant_id == tenant_id, Vehicle.device_id == device_id)
        if exclude_id is not None:
            query = query.filter(Vehicle.id != exclude_id)
        if query.first():
            raise HTTPException(
                409, "That device ID is already assigned to a vehicle")


@app.post("/api/vehicles")
def create_vehicle(body: VehicleCreate, db: Session = Depends(get_db),
                   user: User = Depends(require_roles(*MANAGE_ROLES))):
    tid = _require_tenant(user, body.tenant_id)
    reg_no = body.reg_no.strip().upper()
    device_id = (body.device_id or "").strip() or None
    _check_vehicle_unique(db, tid, reg_no, device_id)
    vehicle = Vehicle(tenant_id=tid, reg_no=reg_no, capacity=body.capacity,
                      device_id=device_id, active=body.active)
    db.add(vehicle)
    db.flush()
    log_audit(db, tenant_id=tid, actor_id=user.id, actor_email=user.email,
              action="VEHICLE_CREATED", entity="vehicle", entity_id=vehicle.id,
              summary=f"Vehicle added: {reg_no}")
    db.commit()
    return _vehicle_json(vehicle)


@app.patch("/api/vehicles/{vehicle_id}")
def update_vehicle(vehicle_id: int, body: VehicleUpdate,
                   db: Session = Depends(get_db),
                   user: User = Depends(require_roles(*MANAGE_ROLES))):
    vehicle = _target_vehicle(db, user, vehicle_id)
    reg_no = vehicle.reg_no
    device_id = vehicle.device_id
    if body.reg_no is not None:
        reg_no = body.reg_no.strip().upper()
    if body.device_id is not None:
        device_id = body.device_id.strip() or None
    _check_vehicle_unique(db, vehicle.tenant_id, reg_no, device_id,
                          exclude_id=vehicle.id)
    vehicle.reg_no = reg_no
    vehicle.device_id = device_id
    if body.capacity is not None:
        vehicle.capacity = body.capacity
    if body.active is not None:
        vehicle.active = body.active
    log_audit(db, tenant_id=vehicle.tenant_id, actor_id=user.id,
              actor_email=user.email, action="VEHICLE_UPDATED", entity="vehicle",
              entity_id=vehicle.id, summary=f"Vehicle updated: {vehicle.reg_no}")
    db.commit()
    return _vehicle_json(vehicle)


class StageIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    order: int | None = Field(default=None, ge=0)
    fare_cents: int = Field(ge=0)


class RouteCreate(BaseModel):
    tenant_id: int | None = None
    name: str = Field(min_length=1, max_length=200)
    stages: list[StageIn] = Field(min_length=1)


class RouteUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    active: bool | None = None


@app.post("/api/routes")
def create_route(body: RouteCreate, db: Session = Depends(get_db),
                 user: User = Depends(require_roles(*MANAGE_ROLES))):
    tid = _require_tenant(user, body.tenant_id)
    name = body.name.strip()
    if db.query(Route).filter(Route.tenant_id == tid,
                              Route.name == name).first():
        raise HTTPException(409, "A route with that name already exists")
    route = Route(tenant_id=tid, name=name)
    db.add(route)
    db.flush()
    for index, stage in enumerate(body.stages):
        db.add(Stage(
            route_id=route.id, name=stage.name.strip(),
            order=stage.order if stage.order is not None else index + 1,
            fare_cents=stage.fare_cents,
        ))
    db.flush()
    log_audit(db, tenant_id=tid, actor_id=user.id, actor_email=user.email,
              action="ROUTE_CREATED", entity="route", entity_id=route.id,
              summary=f"Route added: {name} ({len(body.stages)} stages)")
    db.commit()
    return _route_json(db, route)


@app.patch("/api/routes/{route_id}")
def update_route(route_id: int, body: RouteUpdate,
                 db: Session = Depends(get_db),
                 user: User = Depends(require_roles(*MANAGE_ROLES))):
    route = _target_route(db, user, route_id)
    if body.name is not None:
        name = body.name.strip()
        clash = db.query(Route).filter(
            Route.tenant_id == route.tenant_id, Route.name == name,
            Route.id != route.id).first()
        if clash:
            raise HTTPException(409, "A route with that name already exists")
        route.name = name
    if body.active is not None:
        route.active = body.active
    log_audit(db, tenant_id=route.tenant_id, actor_id=user.id,
              actor_email=user.email, action="ROUTE_UPDATED", entity="route",
              entity_id=route.id, summary=f"Route updated: {route.name}")
    db.commit()
    return _route_json(db, route)


@app.post("/api/routes/{route_id}/stages")
def add_stage(route_id: int, body: StageIn, db: Session = Depends(get_db),
              user: User = Depends(require_roles(*MANAGE_ROLES))):
    route = _target_route(db, user, route_id)
    order = body.order
    if order is None:
        last = (db.query(Stage).filter(Stage.route_id == route.id)
                .order_by(Stage.order.desc()).first())
        order = (last.order + 1) if last else 1
    stage = Stage(route_id=route.id, name=body.name.strip(), order=order,
                  fare_cents=body.fare_cents)
    db.add(stage)
    db.flush()
    log_audit(db, tenant_id=route.tenant_id, actor_id=user.id,
              actor_email=user.email, action="STAGE_CREATED", entity="stage",
              entity_id=stage.id,
              summary=f"Stage added to {route.name}: {stage.name}")
    db.commit()
    return _route_json(db, route)


class StageUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    order: int | None = Field(default=None, ge=0)
    fare_cents: int | None = Field(default=None, ge=0)


@app.patch("/api/stages/{stage_id}")
def update_stage(stage_id: int, body: StageUpdate,
                 db: Session = Depends(get_db),
                 user: User = Depends(require_roles(*MANAGE_ROLES))):
    stage = db.get(Stage, stage_id)
    if stage is None:
        raise HTTPException(404, "Stage not found")
    route = db.get(Route, stage.route_id)
    ensure_tenant(user, route.tenant_id)
    if body.name is not None:
        stage.name = body.name.strip()
    if body.order is not None:
        stage.order = body.order
    if body.fare_cents is not None:
        stage.fare_cents = body.fare_cents
    log_audit(db, tenant_id=route.tenant_id, actor_id=user.id,
              actor_email=user.email, action="STAGE_UPDATED", entity="stage",
              entity_id=stage.id, summary=f"Stage updated: {stage.name}")
    db.commit()
    return _route_json(db, route)


# ---------- transactions ----------

class TransactionCreate(BaseModel):
    tenant_id: int | None = None
    vehicle_id: int
    route_id: int | None = None
    stage_id: int
    shift_id: int | None = None
    conductor_id: int | None = None
    amount_cents: int = Field(gt=0)
    method: str = "CASH"
    occurred_at: datetime | None = None
    external_ref: str | None = None
    idempotency_key: str | None = None
    provider_receipt: str | None = None
    device_id: str | None = None
    device_seq: int | None = None


@app.post("/api/transactions")
def create_transaction(body: TransactionCreate, db: Session = Depends(get_db),
                       user: User = Depends(require_roles(
                           ROLE_PLATFORM, ROLE_SACCO, ROLE_CONDUCTOR))):
    tid = _require_tenant(user, body.tenant_id)
    conductor_id = body.conductor_id
    if user.role == ROLE_CONDUCTOR:
        conductor_id = user.id
    elif conductor_id is None:
        conductor_id = user.id

    tx = integrity.record_transaction(
        db, tenant_id=tid, source="WEB", vehicle_id=body.vehicle_id,
        route_id=body.route_id, stage_id=body.stage_id,
        conductor_id=conductor_id, shift_id=body.shift_id,
        passenger_count=1, amount_cents=body.amount_cents,
        method=body.method, occurred_at=body.occurred_at,
        external_ref=body.external_ref, idempotency_key=body.idempotency_key,
        provider_receipt=body.provider_receipt, device_id=body.device_id,
        device_seq=body.device_seq, strict_fare=False,
    )
    db.commit()
    db.refresh(tx)
    return _tx_json(tx)


@app.get("/api/transactions")
def list_transactions(method: str | None = None,
                      status: str | None = None,
                      integrity_status: str | None = None,
                      source: str | None = None,
                      day: date | None = None,
                      vehicle_id: int | None = None,
                      device_id: str | None = None,
                      shift_id: int | None = None,
                      limit: int = Query(100, ge=1, le=500),
                      tenant_id: int | None = Query(None),
                      db: Session = Depends(get_db),
                      user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(FareTransaction)
    if tid is not None:
        query = query.filter(FareTransaction.tenant_id == tid)
    if user.role == ROLE_CONDUCTOR:
        query = query.filter(FareTransaction.conductor_id == user.id)
    if method:
        query = query.filter(FareTransaction.method == method.upper())
    if status:
        query = query.filter(FareTransaction.status == status.upper())
    if integrity_status:
        query = query.filter(
            FareTransaction.integrity_status == integrity_status.upper())
    if source:
        query = query.filter(FareTransaction.source == source.upper())
    if vehicle_id:
        query = query.filter(FareTransaction.vehicle_id == vehicle_id)
    if device_id:
        query = query.filter(FareTransaction.device_id == device_id)
    if shift_id:
        query = query.filter(FareTransaction.shift_id == shift_id)
    if day:
        start = datetime(day.year, day.month, day.day)
        query = query.filter(
            FareTransaction.occurred_at >= start,
            FareTransaction.occurred_at < start + timedelta(days=1),
        )
    rows = (
        query.order_by(FareTransaction.occurred_at.desc())
        .limit(limit).all()
    )
    return [_tx_json(t) for t in rows]


@app.get("/api/transactions/{tx_id}")
def get_transaction(tx_id: int, db: Session = Depends(get_db),
                    user: User = Depends(current_user)):
    tx = db.get(FareTransaction, tx_id)
    if tx is None:
        raise HTTPException(404, "Transaction not found")
    ensure_tenant(user, tx.tenant_id)
    if user.role == ROLE_CONDUCTOR and tx.conductor_id != user.id:
        raise HTTPException(403, "You can only view your own transactions")
    return _tx_json(tx)


class ReverseBody(BaseModel):
    reason: str = ""


@app.post("/api/transactions/{tx_id}/reverse")
def reverse_transaction(tx_id: int, body: ReverseBody,
                        db: Session = Depends(get_db),
                        user: User = Depends(require_roles(
                            ROLE_PLATFORM, ROLE_SACCO))):
    tx = db.get(FareTransaction, tx_id)
    if tx is None:
        raise HTTPException(404, "Transaction not found")
    ensure_tenant(user, tx.tenant_id)
    integrity.reverse_transaction(
        db, tx, actor_id=user.id, actor_email=user.email,
        reason=body.reason or "reversed by management",
    )
    db.commit()
    db.refresh(tx)
    return _tx_json(tx)


# ---------- ingestion ----------

class IngestBody(BaseModel):
    tenant_id: int | None = None
    source: str = "DEVICE"
    device_id: str | None = None
    vehicle_id: int | None = None
    conductor_id: int | None = None
    shift_id: int | None = None
    reference: str | None = None
    records: list[dict]


class CsvIngestBody(BaseModel):
    tenant_id: int | None = None
    source: str = "CSV"
    device_id: str | None = None
    vehicle_id: int | None = None
    conductor_id: int | None = None
    shift_id: int | None = None
    reference: str | None = None
    csv: str


def _ingest_response(batch: IngestBatch, result: dict, missing: list[int]) -> dict:
    return {
        "batch_id": batch.id,
        "record_count": batch.record_count,
        "accepted_count": batch.accepted_count,
        "duplicate_count": batch.duplicate_count,
        "flagged_count": batch.flagged_count,
        "missing_sequences": missing,
        "duplicates": result["duplicates"],
        "errors": result["errors"],
    }


@app.post("/api/ingest/batch")
def ingest_batch(body: IngestBody, db: Session = Depends(get_db),
                 user: User = Depends(require_roles(
                     ROLE_PLATFORM, ROLE_SACCO))):
    tid = _require_tenant(user, body.tenant_id)
    batch, result, missing = integrity.ingest_records(
        db, tenant_id=tid, source=body.source, records=body.records,
        device_id=body.device_id, vehicle_id=body.vehicle_id,
        conductor_id=body.conductor_id or (user.id if user.role == ROLE_CONDUCTOR else None),
        shift_id=body.shift_id, reference=body.reference,
    )
    db.commit()
    db.refresh(batch)
    return _ingest_response(batch, result, missing)


@app.post("/api/ingest/csv")
def ingest_csv(body: CsvIngestBody, db: Session = Depends(get_db),
               user: User = Depends(require_roles(ROLE_PLATFORM, ROLE_SACCO))):
    tid = _require_tenant(user, body.tenant_id)
    records = integrity.parse_csv(body.csv)
    if not records:
        raise HTTPException(422, "CSV contained no data rows")
    batch, result, missing = integrity.ingest_records(
        db, tenant_id=tid, source=body.source or "CSV", records=records,
        device_id=body.device_id, vehicle_id=body.vehicle_id,
        conductor_id=body.conductor_id, shift_id=body.shift_id,
        reference=body.reference,
    )
    db.commit()
    db.refresh(batch)
    return _ingest_response(batch, result, missing)


@app.get("/api/ingest/batches")
def list_batches(limit: int = 20, tenant_id: int | None = Query(None),
                 db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(IngestBatch)
    if tid is not None:
        query = query.filter(IngestBatch.tenant_id == tid)
    rows = query.order_by(IngestBatch.id.desc()).limit(limit).all()
    return [
        {"id": b.id, "source": b.source, "device_id": b.device_id,
         "vehicle_id": b.vehicle_id, "record_count": b.record_count,
         "accepted_count": b.accepted_count,
         "duplicate_count": b.duplicate_count,
         "flagged_count": b.flagged_count, "gap_count": b.gap_count,
         "received_at": b.received_at.isoformat() if b.received_at else None}
        for b in rows
    ]


# ---------- flags / anomalies ----------

@app.get("/api/flags")
def list_flags(status: str | None = None,
               severity: str | None = None,
               kind: str | None = None,
               day: date | None = None,
               limit: int = Query(100, ge=1, le=500),
               tenant_id: int | None = Query(None),
               db: Session = Depends(get_db),
               user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(IntegrityFlag)
    if tid is not None:
        query = query.filter(IntegrityFlag.tenant_id == tid)
    if status:
        query = query.filter(IntegrityFlag.status == status.upper())
    if severity:
        query = query.filter(IntegrityFlag.severity == severity.upper())
    if kind:
        query = query.filter(IntegrityFlag.kind == kind.upper())
    if day:
        start = datetime(day.year, day.month, day.day)
        query = query.filter(
            IntegrityFlag.detected_at >= start,
            IntegrityFlag.detected_at < start + timedelta(days=1),
        )
    rows = query.order_by(IntegrityFlag.id.desc()).limit(limit).all()
    return [_flag_json(f) for f in rows]


@app.get("/api/flags/summary")
def flags_summary(tenant_id: int | None = Query(None),
                  db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    return _flag_summary(db, tid)


class ResolveBody(BaseModel):
    status: str = "RESOLVED"
    note: str = ""


@app.post("/api/flags/{flag_id}/resolve")
def resolve_flag(flag_id: int, body: ResolveBody,
                 db: Session = Depends(get_db),
                 user: User = Depends(require_roles(ROLE_PLATFORM, ROLE_SACCO))):
    flag = db.get(IntegrityFlag, flag_id)
    if flag is None:
        raise HTTPException(404, "Flag not found")
    ensure_tenant(user, flag.tenant_id)
    new_status = body.status.upper()
    if new_status not in ("OPEN", "INVESTIGATING", "RESOLVED", "DISMISSED"):
        raise HTTPException(422, "Invalid flag status")
    flag.status = new_status
    if new_status in ("RESOLVED", "DISMISSED"):
        flag.resolved_by = user.id
        flag.resolved_at = utcnow()
        flag.resolution_note = body.note[:400]
    log_audit(
        db, tenant_id=flag.tenant_id, actor_id=user.id, actor_email=user.email,
        action="FLAG_UPDATED", entity="integrity_flag", entity_id=flag.id,
        summary=f"Flag {flag.id} ({flag.kind}) -> {new_status}",
        details={"note": body.note, "severity": flag.severity},
    )
    db.commit()
    db.refresh(flag)
    return _flag_json(flag)


# ---------- shifts ----------

@app.get("/api/shifts")
def list_shifts(tenant_id: int | None = Query(None),
                db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(Shift)
    if tid is not None:
        query = query.filter(Shift.tenant_id == tid)
    shifts = query.order_by(Shift.opened_at.desc()).limit(30).all()
    out = []
    for shift in shifts:
        recorded = sum(
            t.amount_cents for t in db.query(FareTransaction).filter(
                FareTransaction.shift_id == shift.id,
                FareTransaction.method == "CASH",
                FareTransaction.status != "REVERSED",
            )
        )
        out.append({
            "id": shift.id, "vehicle_id": shift.vehicle_id,
            "conductor_id": shift.conductor_id,
            "opened_at": shift.opened_at.isoformat() if shift.opened_at else None,
            "closed_at": shift.closed_at.isoformat() if shift.closed_at else None,
            "status": shift.status,
            "declared_cash_cents": shift.declared_cash_cents,
            "recorded_cash_cents": recorded,
            "difference_cents": (shift.declared_cash_cents or 0) - recorded,
        })
    return out


class OpenShiftBody(BaseModel):
    vehicle_id: int


@app.post("/api/shifts/open")
def open_shift(body: OpenShiftBody, db: Session = Depends(get_db),
               user: User = Depends(require_roles(
                   ROLE_PLATFORM, ROLE_SACCO, ROLE_CONDUCTOR))):
    tid = _require_tenant(user, user.tenant_id)
    existing = db.query(Shift).filter(
        Shift.vehicle_id == body.vehicle_id, Shift.status == "OPEN").first()
    if existing:
        raise HTTPException(409, "Vehicle already has an open shift")
    shift = Shift(tenant_id=tid, vehicle_id=body.vehicle_id,
                  conductor_id=user.id)
    db.add(shift)
    db.flush()
    log_audit(
        db, tenant_id=tid, actor_id=user.id, actor_email=user.email,
        action="SHIFT_OPENED", entity="shift", entity_id=shift.id,
        summary=f"vehicle {body.vehicle_id}",
    )
    db.commit()
    return {"id": shift.id, "status": shift.status}


class CloseShiftBody(BaseModel):
    declared_cash_cents: int = Field(ge=0)


@app.post("/api/shifts/{shift_id}/close")
def close_shift(shift_id: int, body: CloseShiftBody,
                db: Session = Depends(get_db),
                user: User = Depends(require_roles(
                    ROLE_PLATFORM, ROLE_SACCO))):
    shift = db.get(Shift, shift_id)
    if shift is None:
        raise HTTPException(404, "Shift not found")
    ensure_tenant(user, shift.tenant_id)
    if shift.status == "CLOSED":
        raise HTTPException(409, "Shift already closed")
    shift.status = "CLOSED"
    shift.closed_at = utcnow()
    shift.declared_cash_cents = body.declared_cash_cents
    db.flush()
    recorded = sum(
        t.amount_cents for t in db.query(FareTransaction).filter(
            FareTransaction.shift_id == shift.id,
            FareTransaction.method == "CASH",
            FareTransaction.status != "REVERSED",
        )
    )
    difference = body.declared_cash_cents - recorded
    log_audit(
        db, tenant_id=shift.tenant_id, actor_id=user.id, actor_email=user.email,
        action="SHIFT_CLOSED", entity="shift", entity_id=shift_id,
        summary=(
            f"declared {body.declared_cash_cents}, recorded {recorded}, "
            f"difference {difference}"
        ),
        details={"recorded_cents": recorded, "difference_cents": difference},
    )
    db.commit()
    return {
        "id": shift.id, "status": "CLOSED",
        "recorded_cash_cents": recorded, "difference_cents": difference,
    }


# ---------- daily vehicle targets ----------

def _target_json(t: DailyTarget, reg_no: str, current_cents: int | None) -> dict:
    return {
        "id": t.id,
        "tenant_id": t.tenant_id,
        "vehicle_id": t.vehicle_id,
        "reg_no": reg_no,
        "day": t.day.isoformat(),
        "current_target_cents": current_cents,
        "target_cents": t.target_cents,
        "target_kes": t.target_cents / 100,
        "declared_cents": t.declared_cents,
        "declared_kes": (
            t.declared_cents / 100 if t.declared_cents is not None else None
        ),
        "declared_by": t.declared_by,
        "declared_at": t.declared_at.isoformat() if t.declared_at else None,
        "declaration_matched": (
            t.declared_cents == t.handed_over_cents
            if t.declared_cents is not None
            and t.handed_over_cents is not None
            else None
        ),
        "handed_over_cents": t.handed_over_cents,
        "handed_over_kes": (
            t.handed_over_cents / 100 if t.handed_over_cents is not None else None
        ),
        "difference_cents": (
            t.handed_over_cents - t.target_cents
            if t.handed_over_cents is not None else None
        ),
        "status": t.status,
        "note": t.note,
        "created_by": t.created_by,
        "handed_over_by": t.handed_over_by,
        "handed_over_at": (
            t.handed_over_at.isoformat() if t.handed_over_at else None
        ),
    }


def _worked_vehicle_ids(db: Session, user: User, tid: int) -> set[int]:
    tx = db.query(FareTransaction.vehicle_id).filter(
        FareTransaction.tenant_id == tid,
        FareTransaction.conductor_id == user.id,
    )
    shifts = db.query(Shift.vehicle_id).filter(
        Shift.tenant_id == tid,
        Shift.conductor_id == user.id,
    )
    return {row[0] for row in tx.all()} | {row[0] for row in shifts.all()}


def _worked_vehicle_on_day(db: Session, user: User, tid: int,
                           vehicle_id: int, day: date) -> bool:
    start = datetime(day.year, day.month, day.day)
    end = start + timedelta(days=1)
    worked = db.query(FareTransaction.id).filter(
        FareTransaction.tenant_id == tid,
        FareTransaction.conductor_id == user.id,
        FareTransaction.vehicle_id == vehicle_id,
        FareTransaction.occurred_at >= start,
        FareTransaction.occurred_at < end,
    ).first()
    shift = db.query(Shift.id).filter(
        Shift.tenant_id == tid,
        Shift.conductor_id == user.id,
        Shift.vehicle_id == vehicle_id,
        Shift.opened_at >= start,
        Shift.opened_at < end,
    ).first()
    return worked is not None or shift is not None


def _standing_json(vehicle: Vehicle, row: DailyTarget | None, day: date) -> dict:
    target = row.target_cents if row is not None else vehicle.daily_target_cents
    return {
        "vehicle_id": vehicle.id,
        "reg_no": vehicle.reg_no,
        "current_target_cents": vehicle.daily_target_cents,
        "current_target_kes": (
            vehicle.daily_target_cents / 100
            if vehicle.daily_target_cents is not None else None
        ),
        "target_updated_at": (
            vehicle.target_updated_at.isoformat()
            if vehicle.target_updated_at else None
        ),
        "day": day.isoformat(),
        "record_id": row.id if row is not None else None,
        "target_cents": target,
        "target_kes": target / 100 if target is not None else None,
        "declared_cents": row.declared_cents if row is not None else None,
        "handed_over_cents": row.handed_over_cents if row is not None else None,
        "difference_cents": (
            row.handed_over_cents - row.target_cents
            if row is not None and row.handed_over_cents is not None else None
        ),
        "declaration_matched": (
            row.declared_cents == row.handed_over_cents
            if row is not None and row.declared_cents is not None
            and row.handed_over_cents is not None else None
        ),
        "status": row.status if row is not None else "PENDING",
        "note": row.note if row is not None else None,
    }


@app.get("/api/targets")
def list_targets(day: date | None = Query(None),
                 tenant_id: int | None = Query(None),
                 db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    day = day or utcnow().date()
    vehicles = db.query(Vehicle)
    if tid is not None:
        vehicles = vehicles.filter(Vehicle.tenant_id == tid)
    if user.role == ROLE_CONDUCTOR:
        vehicles = vehicles.filter(
            Vehicle.id.in_(_worked_vehicle_ids(db, user, tid)))
    rows = db.query(DailyTarget).filter(DailyTarget.day == day)
    if tid is not None:
        rows = rows.filter(DailyTarget.tenant_id == tid)
    by_vehicle = {row.vehicle_id: row for row in rows.all()}
    return [
        _standing_json(vehicle, by_vehicle.get(vehicle.id), day)
        for vehicle in vehicles.order_by(Vehicle.reg_no).all()
    ]


class TargetCreate(BaseModel):
    tenant_id: int | None = None
    vehicle_id: int
    target_cents: int = Field(gt=0)
    note: str | None = None


@app.post("/api/targets")
def set_target(body: TargetCreate, db: Session = Depends(get_db),
               user: User = Depends(require_roles(*MANAGE_ROLES))):
    tid = _require_tenant(user, body.tenant_id)
    vehicle = db.get(Vehicle, body.vehicle_id)
    if vehicle is None or vehicle.tenant_id != tid:
        raise HTTPException(404, "Unknown vehicle for this SACCO")
    previous = vehicle.daily_target_cents
    vehicle.daily_target_cents = body.target_cents
    vehicle.target_updated_at = utcnow()
    vehicle.target_updated_by = user.id
    db.flush()
    log_audit(
        db, tenant_id=tid, actor_id=user.id, actor_email=user.email,
        action="VEHICLE_TARGET_SET", entity="vehicle", entity_id=vehicle.id,
        summary=(
            f"vehicle {vehicle.reg_no}: target "
            f"{integrity.format_kes(body.target_cents)}"
            + (
                f" (was {integrity.format_kes(previous)})"
                if previous is not None else ""
            )
        ),
        details={
            "previous_cents": previous,
            "target_cents": body.target_cents,
            "note": body.note,
        },
    )
    db.commit()
    return _standing_json(vehicle, None, utcnow().date())


class CollectionCreate(BaseModel):
    tenant_id: int | None = None
    vehicle_id: int
    day: date | None = None


@app.post("/api/daily-collections")
def start_collection(body: CollectionCreate, db: Session = Depends(get_db),
                     user: User = Depends(current_user)):
    tid = _require_tenant(user, body.tenant_id)
    vehicle = db.get(Vehicle, body.vehicle_id)
    if vehicle is None or vehicle.tenant_id != tid:
        raise HTTPException(404, "Unknown vehicle for this SACCO")
    day = body.day or utcnow().date()
    if user.role == ROLE_CONDUCTOR and not _worked_vehicle_on_day(
        db, user, tid, vehicle.id, day
    ):
        raise HTTPException(403, "You did not work this vehicle on this day")
    if vehicle.daily_target_cents is None:
        raise HTTPException(409, "No standing target set for this vehicle")
    row = db.query(DailyTarget).filter(
        DailyTarget.tenant_id == tid,
        DailyTarget.vehicle_id == vehicle.id,
        DailyTarget.day == day,
    ).first()
    if row is None:
        row = DailyTarget(
            tenant_id=tid, vehicle_id=vehicle.id, day=day,
            target_cents=vehicle.daily_target_cents, created_by=user.id,
        )
        db.add(row)
        db.flush()
        log_audit(
            db, tenant_id=tid, actor_id=user.id, actor_email=user.email,
            action="DAILY_COLLECTION_STARTED", entity="daily_target",
            entity_id=row.id,
            summary=(
                f"vehicle {vehicle.reg_no} day {day}: collection opened at "
                f"{integrity.format_kes(row.target_cents)}"
            ),
        )
        db.commit()
    return _target_json(row, vehicle.reg_no, vehicle.daily_target_cents)


class DeclarationBody(BaseModel):
    tenant_id: int | None = None
    declared_cents: int = Field(ge=0)
    note: str | None = None


@app.post("/api/targets/{target_id}/declare")
def declare_cash(target_id: int, body: DeclarationBody,
                 db: Session = Depends(get_db),
                 user: User = Depends(require_roles(ROLE_CONDUCTOR))):
    tid = _require_tenant(user, body.tenant_id)
    target = db.get(DailyTarget, target_id)
    if target is None or target.tenant_id != tid:
        raise HTTPException(404, "Unknown daily target")
    if target.declared_cents is not None:
        raise HTTPException(409, "Declaration already logged for this target")
    if target.handed_over_cents is not None:
        raise HTTPException(409, "Handover already logged for this target")

    if not _worked_vehicle_on_day(db, user, tid, target.vehicle_id, target.day):
        raise HTTPException(403, "You did not work this vehicle on this day")

    target.declared_cents = body.declared_cents
    target.declared_by = user.id
    target.declared_at = utcnow()
    if body.note:
        target.note = body.note
    db.flush()

    vehicle = db.get(Vehicle, target.vehicle_id)
    reg_no = vehicle.reg_no if vehicle else str(target.vehicle_id)
    current = vehicle.daily_target_cents if vehicle else None
    log_audit(
        db, tenant_id=tid, actor_id=user.id, actor_email=user.email,
        action="CASH_DECLARED", entity="daily_target", entity_id=target.id,
        summary=(
            f"vehicle {reg_no} day {target.day}: conductor declared "
            f"{integrity.format_kes(body.declared_cents)}"
        ),
        details={
            "declared_cents": body.declared_cents,
            "target_cents": target.target_cents,
        },
    )
    db.commit()
    return _target_json(target, reg_no, current)


class HandoverBody(BaseModel):
    tenant_id: int | None = None
    handed_over_cents: int = Field(ge=0)
    note: str | None = None


@app.post("/api/targets/{target_id}/handover")
def log_handover(target_id: int, body: HandoverBody,
                 db: Session = Depends(get_db),
                 user: User = Depends(require_roles(*MANAGE_ROLES))):
    tid = _require_tenant(user, body.tenant_id)
    target = db.get(DailyTarget, target_id)
    if target is None or target.tenant_id != tid:
        raise HTTPException(404, "Unknown daily target")
    if target.handed_over_cents is not None:
        raise HTTPException(409, "Handover already logged for this target")
    if target.declared_cents is None:
        raise HTTPException(409, "Conductor has not declared an amount yet")

    difference = body.handed_over_cents - target.target_cents
    target.handed_over_cents = body.handed_over_cents
    target.handed_over_by = user.id
    target.handed_over_at = utcnow()
    target.status = (
        "MET" if difference == 0 else "SHORT" if difference < 0 else "OVER"
    )
    if body.note:
        target.note = body.note
    db.flush()

    vehicle = db.get(Vehicle, target.vehicle_id)
    reg_no = vehicle.reg_no if vehicle else str(target.vehicle_id)
    current = vehicle.daily_target_cents if vehicle else None
    if difference != 0:
        integrity.raise_flag(
            db, tenant_id=tid, kind="TARGET_MISMATCH",
            severity="HIGH" if difference < 0 and abs(difference) > 2000 else "MEDIUM",
            dedupe_key=f"target:{tid}:{target.id}",
            detail=(
                f"Vehicle {reg_no} day {target.day}: target "
                f"{integrity.format_kes(target.target_cents)}, handed over "
                f"{integrity.format_kes(body.handed_over_cents)}; "
                f"{'short by' if difference < 0 else 'over by'} "
                f"{integrity.format_kes(abs(difference))}."
            ),
            vehicle_id=target.vehicle_id,
        )

    declaration_gap = body.handed_over_cents - target.declared_cents
    if declaration_gap != 0:
        integrity.raise_flag(
            db, tenant_id=tid, kind="DECLARATION_MISMATCH",
            severity=(
                "HIGH"
                if declaration_gap < 0 and abs(declaration_gap) > 2000
                else "MEDIUM"
            ),
            dedupe_key=f"declare:{tid}:{target.id}",
            detail=(
                f"Vehicle {reg_no} day {target.day}: conductor declared "
                f"{integrity.format_kes(target.declared_cents)}, but "
                f"{integrity.format_kes(body.handed_over_cents)} was counted; "
                f"{'short by' if declaration_gap < 0 else 'over by'} "
                f"{integrity.format_kes(abs(declaration_gap))} versus declaration."
            ),
            vehicle_id=target.vehicle_id,
        )

    log_audit(
        db, tenant_id=tid, actor_id=user.id, actor_email=user.email,
        action="CASH_HANDOVER_LOGGED", entity="daily_target",
        entity_id=target.id,
        summary=(
            f"vehicle {reg_no} day {target.day}: handed over "
            f"{integrity.format_kes(body.handed_over_cents)}, "
            f"target {integrity.format_kes(target.target_cents)}, "
            f"difference {integrity.format_kes(difference)}"
        ),
        details={
            "target_cents": target.target_cents,
            "declared_cents": target.declared_cents,
            "handed_over_cents": body.handed_over_cents,
            "difference_cents": difference,
            "declaration_gap_cents": declaration_gap,
            "declaration_matched": declaration_gap == 0,
            "status": target.status,
        },
    )
    db.commit()
    return _target_json(target, reg_no, current)


# ---------- reconciliation ----------

class ReconcileBody(BaseModel):
    day: date | None = None
    tenant_id: int | None = None


@app.post("/api/reconcile/run")
def run_reconcile(body: ReconcileBody, db: Session = Depends(get_db),
                  user: User = Depends(require_roles(
                      ROLE_PLATFORM, ROLE_SACCO))):
    tid = _require_tenant(user, body.tenant_id)
    tenant = db.get(Tenant, tid)
    day = body.day or utcnow().date()
    run = reconciliation.run_reconciliation(
        db, tenant, datetime.fromisoformat(day.isoformat()),
        actor_id=user.id, actor_email=user.email,
    )
    db.commit()
    db.refresh(run)
    return {
        "id": run.id,
        "summary": json.loads(run.summary),
        "findings_count": run.findings_count,
        "integrity_score": run.integrity_score,
    }


@app.get("/api/reconcile/runs")
def list_reconcile_runs(tenant_id: int | None = Query(None),
                        db: Session = Depends(get_db),
                        user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(ReconciliationRun)
    if tid is not None:
        query = query.filter(ReconciliationRun.tenant_id == tid)
    runs = query.order_by(ReconciliationRun.id.desc()).limit(20).all()
    return [
        {"id": r.id, "period_start": r.period_start.isoformat(),
         "period_end": r.period_end.isoformat(),
         "run_at": r.run_at.isoformat(),
         "summary": json.loads(r.summary) if r.summary else {},
         "findings_count": r.findings_count,
         "integrity_score": r.integrity_score}
        for r in runs
    ]


@app.get("/api/dashboard/stats")
def dashboard_stats(day: date | None = Query(None),
                    tenant_id: int | None = Query(None),
                    db: Session = Depends(get_db),
                    user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    if day is None:
        latest_query = db.query(FareTransaction).filter(
            FareTransaction.status != "REVERSED",
        )
        if tid is not None:
            latest_query = latest_query.filter(FareTransaction.tenant_id == tid)
        if user.role == ROLE_CONDUCTOR:
            latest_query = latest_query.filter(
                FareTransaction.conductor_id == user.id)
        latest = latest_query.order_by(FareTransaction.occurred_at.desc()).first()
        day = latest.occurred_at.date() if latest else utcnow().date()
    start = datetime(day.year, day.month, day.day)
    end = start + timedelta(days=1)

    query = db.query(FareTransaction).filter(
        FareTransaction.occurred_at >= start,
        FareTransaction.occurred_at < end,
        FareTransaction.status != "REVERSED",
    )
    if tid is not None:
        query = query.filter(FareTransaction.tenant_id == tid)
    if user.role == ROLE_CONDUCTOR:
        query = query.filter(FareTransaction.conductor_id == user.id)
    txs = query.all()

    by_method: dict[str, dict] = {}
    by_vehicle: dict[int, dict] = {}
    vehicles = {v.id: v.reg_no for v in db.query(Vehicle).all()}
    for tx in txs:
        bucket = by_method.setdefault(
            tx.method, {"count": 0, "amount_cents": 0})
        bucket["count"] += 1
        bucket["amount_cents"] += tx.amount_cents
        fleet = by_vehicle.setdefault(tx.vehicle_id, {
            "vehicle_id": tx.vehicle_id,
            "reg_no": vehicles.get(tx.vehicle_id, str(tx.vehicle_id)),
            "trips": 0, "amount_cents": 0,
        })
        fleet["trips"] += 1
        fleet["amount_cents"] += tx.amount_cents

    summary = _flag_summary(db, tid)
    recent_query = db.query(IntegrityFlag)
    if tid is not None:
        recent_query = recent_query.filter(IntegrityFlag.tenant_id == tid)
    recent = recent_query.order_by(IntegrityFlag.id.desc()).limit(8).all()

    by_kind = summary["by_kind"]
    return {
        "date": day.isoformat(),
        "transactions_today": len(txs),
        "total_amount_cents": sum(t.amount_cents for t in txs),
        "by_method": by_method,
        "by_vehicle": sorted(
            by_vehicle.values(), key=lambda r: -r["amount_cents"]),
        "integrity_score": integrity.compute_integrity_score(db, tid),
        "open_flags": summary["open"],
        "by_severity": summary["by_severity"],
        "by_kind": by_kind,
        "missing_records": by_kind.get("MISSING_RECORD", 0),
        "duplicate_suspects": sum(
            by_kind.get(k, 0) for k in (
                "DUPLICATE_FINGERPRINT", "DUPLICATE_RECEIPT",
                "DUPLICATE_SUBMISSION")),
        "cash_mismatches": by_kind.get("CASH_MISMATCH", 0),
        "amount_mismatches": by_kind.get("AMOUNT_MISMATCH", 0),
        "recent_flags": [_flag_json(f) for f in recent],
    }


# ---------- reports ----------

def _sales_report(db: Session, tenant_id: int | None, day: date) -> dict:
    start = datetime(day.year, day.month, day.day)
    end = start + timedelta(days=1)
    query = db.query(FareTransaction).filter(
        FareTransaction.occurred_at >= start,
        FareTransaction.occurred_at < end,
    )
    if tenant_id is not None:
        query = query.filter(FareTransaction.tenant_id == tenant_id)
    txs = query.all()
    recorded = [t for t in txs if t.status != "REVERSED"]

    vehicles = {v.id: v.reg_no for v in db.query(Vehicle).all()}
    routes = {r.id: r.name for r in db.query(Route).all()}
    users = {u.id: u.full_name for u in db.query(User).all()}

    by_method: dict[str, dict] = {}
    by_vehicle: dict[int, dict] = {}
    by_route: dict[int, dict] = {}
    by_conductor: dict[int, dict] = {}
    for tx in recorded:
        method = by_method.setdefault(
            tx.method, {"count": 0, "amount_cents": 0})
        method["count"] += 1
        method["amount_cents"] += tx.amount_cents

        vehicle = by_vehicle.setdefault(tx.vehicle_id, {
            "vehicle_id": tx.vehicle_id,
            "reg_no": vehicles.get(tx.vehicle_id, str(tx.vehicle_id)),
            "trips": 0, "amount_cents": 0,
        })
        vehicle["trips"] += 1
        vehicle["amount_cents"] += tx.amount_cents

        route = by_route.setdefault(tx.route_id, {
            "route_id": tx.route_id,
            "name": routes.get(tx.route_id, str(tx.route_id)),
            "trips": 0, "amount_cents": 0,
        })
        route["trips"] += 1
        route["amount_cents"] += tx.amount_cents

        if tx.conductor_id:
            conductor = by_conductor.setdefault(tx.conductor_id, {
                "conductor_id": tx.conductor_id,
                "name": users.get(tx.conductor_id, str(tx.conductor_id)),
                "trips": 0, "amount_cents": 0,
            })
            conductor["trips"] += 1
            conductor["amount_cents"] += tx.amount_cents

    def ordered(rows: dict) -> list[dict]:
        return sorted(rows.values(), key=lambda row: -row["amount_cents"])

    return {
        "day": day.isoformat(),
        "transaction_count": len(recorded),
        "total_amount_cents": sum(t.amount_cents for t in recorded),
        "reversed_count": len(txs) - len(recorded),
        "flagged_count": sum(
            1 for t in recorded if t.integrity_status == "FLAGGED"),
        "by_method": by_method,
        "by_vehicle": ordered(by_vehicle),
        "by_route": ordered(by_route),
        "by_conductor": ordered(by_conductor),
    }


@app.get("/api/reports/sales")
def sales_report(day: date | None = None,
                 tenant_id: int | None = Query(None),
                 db: Session = Depends(get_db),
                 user: User = Depends(require_roles(
                     ROLE_PLATFORM, ROLE_SACCO, ROLE_AUDITOR))):
    tid = _scope(user, tenant_id)
    return _sales_report(db, tid, day or utcnow().date())


@app.get("/api/export/sales.csv")
def export_sales(day: date | None = None,
                 tenant_id: int | None = Query(None),
                 db: Session = Depends(get_db),
                 user: User = Depends(require_roles(
                     ROLE_PLATFORM, ROLE_SACCO, ROLE_AUDITOR))):
    tid = _scope(user, tenant_id)
    report = _sales_report(db, tid, day or utcnow().date())
    rows = [
        [r["vehicle_id"], r["reg_no"], r["trips"],
         r["amount_cents"], f"{r['amount_cents'] / 100:.2f}"]
        for r in report["by_vehicle"]
    ]
    return _csv_response(
        rows,
        ["vehicle_id", "reg_no", "trips", "amount_cents", "amount_kes"],
        f"sales_{report['day']}.csv",
    )


# ---------- audit ----------

@app.get("/api/audit")
def audit_log_list(limit: int = 100,
                   tenant_id: int | None = Query(None),
                   db: Session = Depends(get_db),
                   user: User = Depends(require_roles(
                       ROLE_PLATFORM, ROLE_SACCO, ROLE_AUDITOR))):
    tid = _scope(user, tenant_id)
    query = db.query(AuditLog)
    if tid is not None:
        query = query.filter(AuditLog.tenant_id == tid)
    rows = query.order_by(AuditLog.id.desc()).limit(limit).all()
    return [
        {"id": e.id, "ts": e.ts.isoformat() if e.ts else None,
         "tenant_id": e.tenant_id, "actor_email": e.actor_email,
         "action": e.action, "entity": e.entity, "entity_id": e.entity_id,
         "summary": e.summary, "hash": e.hash[:16]}
        for e in rows
    ]


@app.get("/api/audit/verify")
def audit_verify(db: Session = Depends(get_db),
                 user: User = Depends(require_roles(
                     ROLE_PLATFORM, ROLE_SACCO, ROLE_AUDITOR))):
    return verify_chain(db)


# ---------- exports ----------

def _csv_response(rows: list[list], header: list[str], filename: str) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/export/transactions.csv")
def export_transactions(day: date | None = None,
                        tenant_id: int | None = Query(None),
                        db: Session = Depends(get_db),
                        user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(FareTransaction)
    if tid is not None:
        query = query.filter(FareTransaction.tenant_id == tid)
    if day:
        start = datetime(day.year, day.month, day.day)
        query = query.filter(
            FareTransaction.occurred_at >= start,
            FareTransaction.occurred_at < start + timedelta(days=1),
        )
    rows = query.order_by(FareTransaction.id.asc()).all()
    header = [
        "id", "tenant_id", "source", "external_ref", "device_id", "device_seq",
        "provider_receipt", "vehicle_id", "route_id", "stage_id", "shift_id",
        "conductor_id", "passenger_count", "amount_cents", "method",
        "occurred_at", "received_at", "status", "integrity_status",
    ]
    data = [[
        t.id, t.tenant_id, t.source, t.external_ref, t.device_id, t.device_seq,
        t.provider_receipt, t.vehicle_id, t.route_id, t.stage_id, t.shift_id,
        t.conductor_id, t.passenger_count, t.amount_cents, t.method,
        t.occurred_at.isoformat() if t.occurred_at else "",
        t.received_at.isoformat() if t.received_at else "",
        t.status, t.integrity_status,
    ] for t in rows]
    return _csv_response(data, header, "transactions.csv")


@app.get("/api/export/flags.csv")
def export_flags(tenant_id: int | None = Query(None),
                 db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    query = db.query(IntegrityFlag)
    if tid is not None:
        query = query.filter(IntegrityFlag.tenant_id == tid)
    rows = query.order_by(IntegrityFlag.id.asc()).all()
    header = [
        "id", "tenant_id", "kind", "severity", "transaction_id", "shift_id",
        "device_id", "vehicle_id", "sequence_no", "status", "detected_at",
        "resolved_at", "detail",
    ]
    data = [[
        f.id, f.tenant_id, f.kind, f.severity, f.transaction_id, f.shift_id,
        f.device_id, f.vehicle_id, f.sequence_no, f.status,
        f.detected_at.isoformat() if f.detected_at else "",
        f.resolved_at.isoformat() if f.resolved_at else "",
        _flag_detail(f.detail),
    ] for f in rows]
    return _csv_response(data, header, "integrity_flags.csv")


# ---------- dashboard ----------

@app.get("/")
def serve_index():
    return FileResponse(
        DASHBOARD_DIR / "index.html",
        headers={"Cache-Control": "no-cache"},
    )


app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")
