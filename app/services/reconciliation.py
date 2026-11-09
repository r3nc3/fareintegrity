import json
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .. import integrity
from ..audit import log_audit
from ..models import (
    FareTransaction,
    IntegrityFlag,
    ReconciliationRun,
    Shift,
    Stage,
    Tenant,
)

METHODS = ("CASH", "MPESA", "CARD")


def _period(day: datetime) -> tuple[datetime, datetime]:
    start = datetime(day.year, day.month, day.day)
    return start, start + timedelta(days=1)


def run_reconciliation(db: Session, tenant: Tenant, day: datetime, *,
                       actor_id: int | None = None,
                       actor_email: str | None = None) -> ReconciliationRun:
    start, end = _period(day)

    gaps = integrity.recompute_all_gaps(db, tenant.id)

    txs = (
        db.query(FareTransaction)
        .filter(
            FareTransaction.tenant_id == tenant.id,
            FareTransaction.occurred_at >= start,
            FareTransaction.occurred_at < end,
            FareTransaction.status != "REVERSED",
        )
        .all()
    )

    by_method = {m: {"count": 0, "amount_cents": 0} for m in METHODS}
    stage_cache: dict[int, Stage | None] = {}
    for tx in txs:
        by_method.setdefault(tx.method, {"count": 0, "amount_cents": 0})
        by_method[tx.method]["count"] += 1
        by_method[tx.method]["amount_cents"] += tx.amount_cents

        if tx.stage_id not in stage_cache:
            stage_cache[tx.stage_id] = db.get(Stage, tx.stage_id)
        stage = stage_cache[tx.stage_id]
        if stage:
            expected = stage.fare_cents * tx.passenger_count
            if tx.amount_cents != expected:
                integrity.raise_flag(
                    db, tenant_id=tenant.id, kind="AMOUNT_MISMATCH",
                    severity="HIGH", dedupe_key=f"amt:{tenant.id}:{tx.id}",
                    detail=(
                        f"Ticket {tx.external_ref}: amount {tx.amount_cents} cents "
                        f"does not equal expected fare {expected} cents."
                    ),
                    transaction_id=tx.id, vehicle_id=tx.vehicle_id,
                )
        if tx.source == "WEB" and tx.shift_id is None:
            integrity.raise_flag(
                db, tenant_id=tenant.id, kind="ORPHAN_RECORD", severity="MEDIUM",
                dedupe_key=f"orphan:{tenant.id}:{tx.id}",
                detail=f"Web-recorded ticket {tx.external_ref} is not attached to a shift.",
                transaction_id=tx.id, vehicle_id=tx.vehicle_id,
            )

    groups: dict[str, list[FareTransaction]] = {}
    for tx in txs:
        groups.setdefault(tx.fingerprint, []).append(tx)
    duplicate_groups = 0
    for fingerprint, group in groups.items():
        if len(group) > 1:
            duplicate_groups += 1
            tickets = ", ".join(t.external_ref for t in group)
            integrity.raise_flag(
                db, tenant_id=tenant.id, kind="DUPLICATE_FINGERPRINT",
                severity="HIGH", dedupe_key=f"fp:{tenant.id}:{fingerprint}",
                detail=(
                    f"{len(group)} transactions share the same fingerprint "
                    f"(tickets {tickets}). Suspected duplicate charges."
                ),
                transaction_id=group[0].id, vehicle_id=group[0].vehicle_id,
            )

    cash_mismatches = 0
    closed_shifts = (
        db.query(Shift)
        .filter(
            Shift.tenant_id == tenant.id,
            Shift.status == "CLOSED",
            Shift.closed_at >= start,
            Shift.closed_at < end,
        )
        .all()
    )
    for shift in closed_shifts:
        recorded = sum(
            t.amount_cents
            for t in db.query(FareTransaction).filter(
                FareTransaction.shift_id == shift.id,
                FareTransaction.method == "CASH",
                FareTransaction.status != "REVERSED",
            )
        )
        declared = shift.declared_cash_cents or 0
        if recorded != declared:
            cash_mismatches += 1
            difference = declared - recorded
            integrity.raise_flag(
                db, tenant_id=tenant.id, kind="CASH_MISMATCH",
                severity="HIGH" if abs(difference) > 2000 else "MEDIUM",
                dedupe_key=f"cash:{tenant.id}:{shift.id}",
                detail=(
                    f"Shift {shift.id} (vehicle {shift.vehicle_id}): declared "
                    f"{declared} cents vs recorded {recorded} cents; difference "
                    f"{difference} cents."
                ),
                shift_id=shift.id, vehicle_id=shift.vehicle_id,
            )

    open_flags = (
        db.query(IntegrityFlag)
        .filter(
            IntegrityFlag.tenant_id == tenant.id,
            IntegrityFlag.status.in_(("OPEN", "INVESTIGATING")),
        )
        .all()
    )
    summary = {
        "period": start.date().isoformat(),
        "transaction_count": len(txs),
        "by_method": by_method,
        "total_amount_cents": sum(
            by_method[m]["amount_cents"] for m in by_method
        ),
        "device_gaps": {d: seqs for d, seqs in gaps.items() if seqs},
        "duplicate_groups": duplicate_groups,
        "cash_mismatches": cash_mismatches,
        "open_flags": len(open_flags),
    }
    score = integrity.compute_integrity_score(db, tenant.id)
    run = ReconciliationRun(
        tenant_id=tenant.id,
        period_start=start,
        period_end=end,
        summary=json.dumps(summary),
        findings_count=len(open_flags),
        integrity_score=score,
    )
    db.add(run)
    db.flush()
    log_audit(
        db, tenant_id=tenant.id, actor_id=actor_id, actor_email=actor_email,
        action="RECONCILIATION_RUN", entity="reconciliation_run", entity_id=run.id,
        summary=(
            f"Reconciled {start.date()}: {len(txs)} transactions, "
            f"{len(open_flags)} open flags, score {score}"
        ),
        details=summary,
    )
    return run
