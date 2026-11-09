"""Core integrity engine: validation, duplicate prevention, gap detection, flagging."""

import csv
import hashlib
import io
import json
import secrets
import string
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import log_audit
from .models import (
    FareTransaction,
    IngestBatch,
    IntegrityFlag,
    Route,
    Stage,
    User,
    Vehicle,
    utcnow,
)

METHODS = ("CASH", "MPESA", "CARD")
SOURCES = ("WEB", "DEVICE", "CSV", "API")
FINGERPRINT_WINDOW = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(minutes=5)

SEVERITY_PENALTY = {"HIGH": 8, "MEDIUM": 3, "LOW": 1}


class IntegrityViolation(Exception):
    code = "integrity_error"
    status_code = 422


class FareValidationError(IntegrityViolation):
    code = "fare_validation_failed"
    status_code = 422


class DuplicateTransaction(IntegrityViolation):
    status_code = 409

    def __init__(self, message, existing=None, code="duplicate_transaction"):
        super().__init__(message)
        self.existing = existing
        self.code = code


class IngestError(IntegrityViolation):
    code = "ingest_error"
    status_code = 400


def _rand(prefix: str, n: int = 10) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return prefix + "-" + "".join(secrets.choice(alphabet) for _ in range(n))


def make_fingerprint(*, tenant_id, device_id, conductor_id, vehicle_id, stage_id,
                     method, amount_cents, passenger_count, occurred_at) -> str:
    bucket = occurred_at.replace(second=0, microsecond=0)
    bucket = bucket.replace(minute=bucket.minute - (bucket.minute % 5))
    payload = "|".join(str(x) for x in [
        tenant_id, device_id or "", conductor_id or "", vehicle_id, stage_id,
        method, amount_cents, passenger_count, bucket.isoformat(),
    ])
    return hashlib.sha256(payload.encode()).hexdigest()


def raise_flag(db: Session, *, tenant_id: int, kind: str, severity: str,
               dedupe_key: str, detail: str, transaction_id: int | None = None,
               shift_id: int | None = None, device_id: str | None = None,
               vehicle_id: int | None = None, sequence_no: int | None = None):
    existing = (
        db.query(IntegrityFlag)
        .filter(IntegrityFlag.tenant_id == tenant_id,
                IntegrityFlag.dedupe_key == dedupe_key)
        .first()
    )
    if existing:
        if existing.status in ("OPEN", "INVESTIGATING"):
            existing.detail = detail
            existing.severity = severity
        return existing, False

    flag = IntegrityFlag(
        tenant_id=tenant_id, kind=kind, severity=severity,
        transaction_id=transaction_id, shift_id=shift_id, device_id=device_id,
        vehicle_id=vehicle_id, sequence_no=sequence_no, detail=detail,
        dedupe_key=dedupe_key, status="OPEN",
    )
    db.add(flag)
    db.flush()
    if transaction_id:
        tx = db.get(FareTransaction, transaction_id)
        if tx:
            tx.integrity_status = "FLAGGED"
    log_audit(
        db, tenant_id=tenant_id, action="FLAG_RAISED", entity="integrity_flag",
        entity_id=flag.id, summary=detail[:400],
        details={"kind": kind, "severity": severity, "sequence_no": sequence_no},
    )
    return flag, True


def record_transaction(db: Session, *, tenant_id: int, source: str = "WEB",
                       vehicle_id: int, stage_id: int, route_id: int | None = None,
                       conductor_id: int | None = None, shift_id: int | None = None,
                       passenger_count: int = 1, amount_cents: int, method: str = "CASH",
                       occurred_at: datetime | None = None, external_ref: str | None = None,
                       idempotency_key: str | None = None,
                       provider_receipt: str | None = None, device_id: str | None = None,
                       device_seq: int | None = None, raw_details: dict | None = None,
                       strict_fare: bool = True) -> FareTransaction:
    method = (method or "CASH").upper()
    source = (source or "WEB").upper()
    if method not in METHODS:
        raise FareValidationError(f"Unsupported method {method}")
    if source not in SOURCES:
        raise FareValidationError(f"Unsupported source {source}")

    stage = db.get(Stage, stage_id)
    if stage is None:
        raise FareValidationError("Unknown stage")
    vehicle = db.get(Vehicle, vehicle_id)
    if vehicle is None or vehicle.tenant_id != tenant_id:
        raise FareValidationError("Unknown vehicle for this SACCO")
    route_id = route_id or stage.route_id
    route = db.get(Route, route_id)
    if route is None or route.tenant_id != tenant_id or stage.route_id != route_id:
        raise FareValidationError("Stage does not belong to the selected route")

    if passenger_count < 1:
        raise FareValidationError("passenger_count must be at least 1")
    if passenger_count > vehicle.capacity:
        raise FareValidationError(
            f"passenger_count {passenger_count} exceeds vehicle capacity {vehicle.capacity}"
        )

    occurred_at = occurred_at or utcnow()
    if occurred_at > utcnow() + MAX_CLOCK_SKEW:
        raise FareValidationError("occurred_at is in the future (clock skew rejected)")

    expected = stage.fare_cents * passenger_count
    if strict_fare and amount_cents != expected:
        raise FareValidationError(
            f"Fare validation failed: expected {expected} cents for "
            f"{passenger_count} passenger(s) at {stage.name}, got {amount_cents}"
        )

    idempotency_key = idempotency_key or _rand("IDEM")
    existing = db.query(FareTransaction).filter(
        FareTransaction.tenant_id == tenant_id,
        FareTransaction.idempotency_key == idempotency_key,
    ).first()
    if existing:
        raise DuplicateTransaction(
            "Idempotency key already used; original transaction returned",
            existing, "duplicate_idempotency",
        )

    external_ref = external_ref or _rand("TKT")
    existing = db.query(FareTransaction).filter(
        FareTransaction.tenant_id == tenant_id,
        FareTransaction.external_ref == external_ref,
    ).first()
    if existing:
        raise DuplicateTransaction(
            f"Ticket reference {external_ref} is already recorded",
            existing, "duplicate_ticket",
        )

    if provider_receipt:
        existing = db.query(FareTransaction).filter(
            FareTransaction.tenant_id == tenant_id,
            FareTransaction.provider_receipt == provider_receipt,
        ).first()
        if existing:
            raise DuplicateTransaction(
                f"Provider receipt {provider_receipt} is already recorded",
                existing, "duplicate_receipt",
            )

    if device_id and device_seq is not None:
        existing = db.query(FareTransaction).filter(
            FareTransaction.tenant_id == tenant_id,
            FareTransaction.device_id == device_id,
            FareTransaction.device_seq == device_seq,
        ).first()
        if existing:
            raise DuplicateTransaction(
                f"Device {device_id} sequence {device_seq} is already recorded",
                existing, "duplicate_sequence",
            )

    fingerprint = make_fingerprint(
        tenant_id=tenant_id, device_id=device_id, conductor_id=conductor_id,
        vehicle_id=vehicle_id, stage_id=stage_id, method=method,
        amount_cents=amount_cents, passenger_count=passenger_count,
        occurred_at=occurred_at,
    )

    tx = FareTransaction(
        tenant_id=tenant_id, source=source, external_ref=external_ref,
        idempotency_key=idempotency_key, device_id=device_id,
        device_seq=device_seq, provider_receipt=provider_receipt,
        fingerprint=fingerprint, vehicle_id=vehicle_id, route_id=route_id,
        stage_id=stage_id, shift_id=shift_id, conductor_id=conductor_id,
        passenger_count=passenger_count, amount_cents=amount_cents, method=method,
        occurred_at=occurred_at, received_at=utcnow(), status="RECORDED",
        integrity_status="OK",
        raw_details=json.dumps(raw_details, default=str) if raw_details else None,
    )
    try:
        with db.begin_nested():
            db.add(tx)
            db.flush()
    except IntegrityError as exc:
        raise DuplicateTransaction(
            "Duplicate transaction rejected by a database uniqueness constraint",
            None, "duplicate_constraint",
        ) from exc

    collision = db.query(FareTransaction).filter(
        FareTransaction.tenant_id == tenant_id,
        FareTransaction.fingerprint == fingerprint,
        FareTransaction.id != tx.id,
        FareTransaction.status != "REVERSED",
        FareTransaction.occurred_at >= occurred_at - FINGERPRINT_WINDOW,
        FareTransaction.occurred_at <= occurred_at + FINGERPRINT_WINDOW,
    ).first()
    if collision:
        raise_flag(
            db, tenant_id=tenant_id, kind="DUPLICATE_FINGERPRINT", severity="HIGH",
            dedupe_key=f"fp:{tenant_id}:{fingerprint}",
            detail=(
                f"Suspected duplicate charge: transaction {tx.id} matches "
                f"transaction {collision.id} (same vehicle/stage/method/amount "
                f"within 5 minutes)."
            ),
            transaction_id=tx.id, vehicle_id=vehicle_id, device_id=device_id,
        )

    if amount_cents != expected:
        raise_flag(
            db, tenant_id=tenant_id, kind="AMOUNT_MISMATCH", severity="HIGH",
            dedupe_key=f"amt:{tenant_id}:{tx.id}",
            detail=(
                f"Amount {amount_cents} cents does not equal expected fare "
                f"{expected} cents ({passenger_count} x {stage.fare_cents})."
            ),
            transaction_id=tx.id, vehicle_id=vehicle_id,
        )

    log_audit(
        db, tenant_id=tenant_id, actor_id=conductor_id,
        action="TRANSACTION_RECORDED", entity="transaction", entity_id=tx.id,
        summary=(
            f"{source} {method} {amount_cents} cents, ticket {external_ref}, "
            f"vehicle {vehicle_id}, stage {stage.name}"
        ),
        details={
            "source": source, "method": method, "amount_cents": amount_cents,
            "expected_cents": expected, "device_id": device_id,
            "device_seq": device_seq, "integrity_status": tx.integrity_status,
        },
    )
    return tx


def recompute_device_gaps(db: Session, tenant_id: int, device_id: str) -> list[int]:
    rows = (
        db.query(FareTransaction.device_seq)
        .filter(
            FareTransaction.tenant_id == tenant_id,
            FareTransaction.device_id == device_id,
            FareTransaction.device_seq.isnot(None),
            FareTransaction.status != "REVERSED",
        )
        .all()
    )
    seqs = {r[0] for r in rows}
    if not seqs:
        return []

    lo, hi = min(seqs), max(seqs)
    missing = [s for s in range(lo, hi + 1) if s not in seqs]
    for seq in missing:
        raise_flag(
            db, tenant_id=tenant_id, kind="MISSING_RECORD", severity="HIGH",
            dedupe_key=f"gap:{tenant_id}:{device_id}:{seq}",
            detail=(
                f"Device {device_id} sequence {seq} is missing in observed "
                f"range {lo}-{hi}. A fare record may have been lost or suppressed."
            ),
            device_id=device_id, sequence_no=seq,
        )

    open_gaps = (
        db.query(IntegrityFlag)
        .filter(
            IntegrityFlag.tenant_id == tenant_id,
            IntegrityFlag.kind == "MISSING_RECORD",
            IntegrityFlag.device_id == device_id,
            IntegrityFlag.status.in_(("OPEN", "INVESTIGATING")),
        )
        .all()
    )
    for flag in open_gaps:
        if flag.sequence_no in seqs:
            flag.status = "RESOLVED"
            flag.resolved_at = utcnow()
            flag.resolution_note = "Record later arrived via ingestion."
    return missing


def recompute_all_gaps(db: Session, tenant_id: int) -> dict:
    devices = {
        r[0] for r in db.query(FareTransaction.device_id)
        .filter(FareTransaction.tenant_id == tenant_id,
                FareTransaction.device_id.isnot(None))
        .distinct().all()
    }
    result = {}
    for device in devices:
        result[device] = recompute_device_gaps(db, tenant_id, device)
    return result


def _pick(raw: dict, *keys):
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


def normalize_record(db: Session, tenant_id: int, raw: dict, *,
                     default_device_id=None, default_vehicle_id=None,
                     default_conductor_id=None, default_shift_id=None) -> dict:
    vehicle_id = _pick(raw, "vehicle_id") or default_vehicle_id
    if not vehicle_id:
        reg = _pick(raw, "reg_no", "vehicle_reg", "vehicle")
        if reg:
            vehicle = db.query(Vehicle).filter(
                Vehicle.tenant_id == tenant_id, Vehicle.reg_no == reg).first()
            vehicle_id = vehicle.id if vehicle else None
    if not vehicle_id:
        raise IngestError("Record is missing vehicle_id / reg_no")

    stage_id = _pick(raw, "stage_id")
    if not stage_id:
        name = _pick(raw, "stage", "stage_name")
        if name:
            stage = (
                db.query(Stage).join(Route)
                .filter(Route.tenant_id == tenant_id, Stage.name == name)
                .first()
            )
            stage_id = stage.id if stage else None
    if not stage_id:
        raise IngestError("Record is missing stage_id / stage name")

    route_id = _pick(raw, "route_id")
    if not route_id:
        stage = db.get(Stage, int(stage_id))
        route_id = stage.route_id if stage else None

    conductor_id = _pick(raw, "conductor_id") or default_conductor_id
    if not conductor_id:
        email = _pick(raw, "conductor_email", "email")
        if email:
            user = db.query(User).filter(User.email == str(email).lower()).first()
            conductor_id = user.id if user else None

    shift_id = _pick(raw, "shift_id") or default_shift_id

    amount_cents = _pick(raw, "amount_cents")
    if amount_cents is None:
        amount = _pick(raw, "amount", "amount_kes", "fare")
        amount_cents = int(round(float(amount) * 100)) if amount is not None else None
    if amount_cents is None:
        raise IngestError("Record is missing amount_cents / amount")

    occurred = _pick(raw, "occurred_at", "timestamp", "time")
    if isinstance(occurred, str):
        try:
            occurred = datetime.fromisoformat(occurred.replace("Z", "+00:00"))
            occurred = occurred.replace(tzinfo=None)
        except ValueError as exc:
            raise IngestError(f"Invalid occurred_at value {occurred!r}") from exc
    elif occurred is None:
        occurred = utcnow()

    passengers = _pick(raw, "passenger_count", "passengers", "pax") or 1
    device_seq = _pick(raw, "device_seq", "seq", "sequence")
    return {
        "vehicle_id": int(vehicle_id),
        "route_id": int(route_id) if route_id else None,
        "stage_id": int(stage_id),
        "conductor_id": int(conductor_id) if conductor_id else None,
        "shift_id": int(shift_id) if shift_id else None,
        "passenger_count": int(passengers),
        "amount_cents": int(amount_cents),
        "method": str(_pick(raw, "method", "tender") or "CASH").upper(),
        "occurred_at": occurred,
        "external_ref": _pick(raw, "external_ref", "ticket_ref", "ticket", "receipt_no"),
        "idempotency_key": _pick(raw, "idempotency_key"),
        "provider_receipt": _pick(raw, "provider_receipt", "receipt", "mpesa_receipt"),
        "device_id": _pick(raw, "device_id") or default_device_id,
        "device_seq": int(device_seq) if device_seq is not None else None,
        "raw_details": raw,
    }


def parse_csv(text: str) -> list[dict]:
    try:
        reader = csv.DictReader(io.StringIO(text.strip()))
        return [dict(row) for row in reader]
    except Exception as exc:
        raise IngestError(f"Could not parse CSV: {exc}") from exc


def ingest_records(db: Session, *, tenant_id: int, source: str, records: list[dict],
                   device_id: str | None = None, vehicle_id: int | None = None,
                   conductor_id: int | None = None, shift_id: int | None = None,
                   reference: str | None = None):
    source = (source or "DEVICE").upper()
    batch = IngestBatch(
        tenant_id=tenant_id, source=source, device_id=device_id,
        vehicle_id=vehicle_id, reference=reference, record_count=len(records),
    )
    db.add(batch)
    db.flush()

    accepted, duplicates, errors, flagged = [], [], [], []
    for raw in records:
        try:
            normalized = normalize_record(
                db, tenant_id, raw, default_device_id=device_id,
                default_vehicle_id=vehicle_id, default_conductor_id=conductor_id,
                default_shift_id=shift_id,
            )
            tx = record_transaction(
                db, tenant_id=tenant_id, source=source, strict_fare=False,
                **normalized,
            )
            accepted.append(tx.id)
            if tx.integrity_status == "FLAGGED":
                flagged.append(tx.id)
        except DuplicateTransaction as exc:
            duplicates.append({
                "ref": raw.get("external_ref") or raw.get("ticket_ref"),
                "reason": exc.code,
                "existing_id": exc.existing.id if exc.existing else None,
            })
            if exc.code in ("duplicate_receipt", "duplicate_sequence"):
                kind = ("DUPLICATE_RECEIPT" if exc.code == "duplicate_receipt"
                        else "DUPLICATE_SUBMISSION")
                key = raw.get("provider_receipt") or raw.get("receipt") or raw.get("device_seq")
                raise_flag(
                    db, tenant_id=tenant_id, kind=kind, severity="HIGH",
                    dedupe_key=f"{exc.code}:{tenant_id}:{key}",
                    detail=f"Ingested record duplicates an existing record ({exc.code}).",
                    transaction_id=exc.existing.id if exc.existing else None,
                    device_id=device_id,
                )
        except IntegrityViolation as exc:
            errors.append({
                "ref": raw.get("external_ref") or raw.get("ticket_ref"),
                "error": str(exc),
            })

    missing = recompute_device_gaps(db, tenant_id, device_id) if device_id else []
    batch.accepted_count = len(accepted)
    batch.duplicate_count = len(duplicates)
    batch.flagged_count = len(flagged)
    batch.gap_count = len(missing)
    batch.note = json.dumps({"errors": errors[:20]})

    log_audit(
        db, tenant_id=tenant_id, action="BATCH_INGESTED", entity="ingest_batch",
        entity_id=batch.id,
        summary=(
            f"{source} batch {batch.id}: {batch.accepted_count} accepted, "
            f"{batch.duplicate_count} duplicate, {batch.gap_count} gaps"
        ),
        details={
            "device_id": device_id, "record_count": len(records),
            "accepted": batch.accepted_count, "duplicates": batch.duplicate_count,
            "errors": len(errors), "gaps": missing,
        },
    )
    return batch, {"accepted": accepted, "duplicates": duplicates,
                   "errors": errors, "flagged": flagged}, missing


def reverse_transaction(db: Session, tx: FareTransaction, *, actor_id: int,
                        actor_email: str | None, reason: str) -> FareTransaction:
    if tx.status == "REVERSED":
        raise IntegrityViolation("Transaction is already reversed")
    tx.status = "REVERSED"
    tx.reversal_reason = reason[:300]
    tx.reversed_at = utcnow()
    tx.reversed_by = actor_id
    log_audit(
        db, tenant_id=tx.tenant_id, actor_id=actor_id, actor_email=actor_email,
        action="TRANSACTION_REVERSED", entity="transaction", entity_id=tx.id,
        summary=f"Reversed ticket {tx.external_ref}: {reason[:200]}",
        details={"amount_cents": tx.amount_cents, "reason": reason},
    )
    return tx


def compute_integrity_score(db: Session, tenant_id: int | None) -> int:
    query = db.query(IntegrityFlag).filter(
        IntegrityFlag.status.in_(("OPEN", "INVESTIGATING")))
    if tenant_id is not None:
        query = query.filter(IntegrityFlag.tenant_id == tenant_id)
    penalty = sum(
        SEVERITY_PENALTY.get(flag.severity, 1) for flag in query.all()
    )
    return max(0, 100 - penalty)
