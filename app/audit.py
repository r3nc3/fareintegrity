import hashlib
import json

from sqlalchemy.orm import Session

from .models import AuditLog, utcnow

GENESIS = hashlib.sha256(b"fareguard-genesis").hexdigest()


def _canonical(prev_hash: str, ts, tenant_id, actor_email: str, action: str,
               entity: str, entity_id: int | None, summary: str,
               details_json: str | None) -> str:
    payload = {
        "prev": prev_hash,
        "ts": ts.isoformat(),
        "tenant": tenant_id,
        "actor": actor_email,
        "action": action,
        "entity": entity,
        "entity_id": entity_id,
        "summary": summary,
        "details": details_json,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def log_audit(db: Session, *, action: str, entity: str, summary: str = "",
              tenant_id: int | None = None, actor_id: int | None = None,
              actor_email: str | None = None, entity_id: int | None = None,
              details: dict | None = None) -> AuditLog:
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(1).one_or_none()
    prev_hash = last.hash if last else GENESIS
    ts = utcnow()
    details_json = (
        json.dumps(details, sort_keys=True, separators=(",", ":"))
        if details else None
    )
    entry = AuditLog(
        ts=ts,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        entity=entity,
        entity_id=entity_id,
        summary=summary,
        details=details_json,
        prev_hash=prev_hash,
        hash="",
    )
    entry.hash = hashlib.sha256(
        _canonical(prev_hash, ts, tenant_id, actor_email or "", action,
                   entity, entity_id, summary, details_json).encode()
    ).hexdigest()
    db.add(entry)
    # Flush so a second audit entry in the same transaction chains onto this one.
    db.flush()
    return entry


def verify_chain(db: Session) -> dict:
    entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    prev = GENESIS
    for i, e in enumerate(entries):
        recomputed = hashlib.sha256(
            _canonical(e.prev_hash, e.ts, e.tenant_id, e.actor_email or "",
                       e.action, e.entity, e.entity_id, e.summary,
                       e.details).encode()
        ).hexdigest()
        if e.prev_hash != prev:
            return {
                "ok": False,
                "entries_checked": i,
                "broken_first_index": i,
                "issue": f"entry {e.id} prev_hash does not match previous chain link",
            }
        if e.hash != recomputed:
            return {
                "ok": False,
                "entries_checked": i,
                "broken_first_index": i,
                "issue": f"entry {e.id} hash was tampered",
            }
        prev = e.hash
    return {"ok": True, "entries_checked": len(entries)}
