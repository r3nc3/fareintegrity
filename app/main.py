import csv
import io
import json
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import integrity
from .audit import log_audit, verify_chain
from .db import Base, engine, get_db
from .models import (
    AuditLog,
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

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT / "dashboard"


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(bind=engine)
    with Session(engine) as db:
        seed_db(db)
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
        "detail": f.detail,
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

class LoginBody(BaseModel):
    email: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    if not user.active:
        raise HTTPException(403, "Account disabled")
    log_audit(
        db, tenant_id=user.tenant_id, actor_id=user.id, actor_email=user.email,
        action="LOGIN", entity="user", entity_id=user.id, summary="login success",
    )
    db.commit()
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
    return [
        {"id": v.id, "tenant_id": v.tenant_id, "reg_no": v.reg_no,
         "capacity": v.capacity, "device_id": v.device_id, "active": v.active}
        for v in query.all()
    ]


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
            "stages": [
                {"id": s.id, "name": s.name, "order": s.order,
                 "fare_cents": s.fare_cents, "fare_kes": s.fare_cents / 100}
                for s in stages
            ],
        })
    return out


# ---------- transactions ----------

class TransactionCreate(BaseModel):
    tenant_id: int | None = None
    vehicle_id: int
    route_id: int | None = None
    stage_id: int
    shift_id: int | None = None
    conductor_id: int | None = None
    passenger_count: int = Field(default=1, ge=1)
    amount_cents: int = Field(ge=0)
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
        passenger_count=body.passenger_count, amount_cents=body.amount_cents,
        method=body.method, occurred_at=body.occurred_at,
        external_ref=body.external_ref, idempotency_key=body.idempotency_key,
        provider_receipt=body.provider_receipt, device_id=body.device_id,
        device_seq=body.device_seq,
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
                     ROLE_PLATFORM, ROLE_SACCO, ROLE_CONDUCTOR))):
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
                    ROLE_PLATFORM, ROLE_SACCO, ROLE_CONDUCTOR))):
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
def dashboard_stats(tenant_id: int | None = Query(None),
                    db: Session = Depends(get_db),
                    user: User = Depends(current_user)):
    tid = _scope(user, tenant_id)
    today = utcnow().date()
    start = datetime(today.year, today.month, today.day)

    query = db.query(FareTransaction).filter(
        FareTransaction.occurred_at >= start,
        FareTransaction.status != "REVERSED",
    )
    if tid is not None:
        query = query.filter(FareTransaction.tenant_id == tid)
    txs = query.all()

    by_method: dict[str, dict] = {}
    for tx in txs:
        bucket = by_method.setdefault(
            tx.method, {"count": 0, "amount_cents": 0})
        bucket["count"] += 1
        bucket["amount_cents"] += tx.amount_cents

    summary = _flag_summary(db, tid)
    recent_query = db.query(IntegrityFlag)
    if tid is not None:
        recent_query = recent_query.filter(IntegrityFlag.tenant_id == tid)
    recent = recent_query.order_by(IntegrityFlag.id.desc()).limit(8).all()

    by_kind = summary["by_kind"]
    return {
        "date": today.isoformat(),
        "transactions_today": len(txs),
        "total_amount_cents": sum(t.amount_cents for t in txs),
        "by_method": by_method,
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
        f.detail,
    ] for f in rows]
    return _csv_response(data, header, "integrity_flags.csv")


# ---------- dashboard ----------

@app.get("/")
def serve_index():
    return FileResponse(DASHBOARD_DIR / "index.html")


app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")
