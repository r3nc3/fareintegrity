from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import relationship

from .db import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    region = Column(String(120))
    contact_email = Column(String(150))
    subscription_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    users = relationship("User", back_populates="tenant")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"),)

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)
    email = Column(String(150), nullable=False)
    password_hash = Column(String(300), nullable=False)
    full_name = Column(String(150), nullable=False)
    # PLATFORM_ADMIN | SACCO_ADMIN | CONDUCTOR | AUDITOR
    role = Column(String(30), nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    tenant = relationship("Tenant", back_populates="users")


class Vehicle(Base):
    __tablename__ = "vehicles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "reg_no", name="uq_vehicle_reg"),
        UniqueConstraint("tenant_id", "device_id", name="uq_vehicle_device"),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    reg_no = Column(String(40), nullable=False)
    capacity = Column(Integer, default=14)
    device_id = Column(String(80), nullable=True)  # fare device / POS terminal id
    active = Column(Boolean, default=True)


class Route(Base):
    __tablename__ = "routes"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    name = Column(String(200), nullable=False)
    active = Column(Boolean, default=True)

    stages = relationship(
        "Stage", back_populates="route", order_by="Stage.order",
        cascade="all, delete-orphan",
    )


class Stage(Base):
    __tablename__ = "stages"

    id = Column(Integer, primary_key=True)
    route_id = Column(Integer, ForeignKey("routes.id"), nullable=False)
    name = Column(String(150), nullable=False)
    order = Column(Integer, default=0)
    fare_cents = Column(Integer, nullable=False)

    route = relationship("Route", back_populates="stages")


class Shift(Base):
    __tablename__ = "shifts"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    conductor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    opened_at = Column(DateTime, default=utcnow)
    closed_at = Column(DateTime, nullable=True)
    declared_cash_cents = Column(Integer, nullable=True)  # physical cash counted at close
    status = Column(String(20), default="OPEN")  # OPEN | CLOSED

    transactions = relationship("FareTransaction", back_populates="shift")


class FareTransaction(Base):
    """A single fare record. Immutable except for reversal status; never edited."""

    __tablename__ = "transactions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "external_ref", name="uq_tx_external_ref"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_tx_idempotency"),
        Index(
            "uq_tx_device_seq", "tenant_id", "device_id", "device_seq",
            unique=True, sqlite_where=text("device_seq IS NOT NULL"),
        ),
        Index(
            "uq_tx_provider_receipt", "tenant_id", "provider_receipt",
            unique=True, sqlite_where=text("provider_receipt IS NOT NULL"),
        ),
        Index("ix_tx_tenant_occurred", "tenant_id", "occurred_at"),
        Index("ix_tx_tenant_status", "tenant_id", "status"),
        Index("ix_tx_fingerprint", "tenant_id", "fingerprint"),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    source = Column(String(12), nullable=False, default="WEB")  # WEB | DEVICE | CSV | API

    # Identity / dedup keys
    external_ref = Column(String(120), nullable=False)      # ticket / receipt reference
    idempotency_key = Column(String(120), nullable=False)
    device_id = Column(String(80), nullable=True)
    device_seq = Column(Integer, nullable=True)
    provider_receipt = Column(String(120), nullable=True)   # external proof reference
    fingerprint = Column(String(80), nullable=False)

    # Trip details
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    route_id = Column(Integer, ForeignKey("routes.id"), nullable=False)
    stage_id = Column(Integer, ForeignKey("stages.id"), nullable=False)
    shift_id = Column(Integer, ForeignKey("shifts.id"), nullable=True)
    conductor_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    passenger_count = Column(Integer, nullable=False, default=1)
    amount_cents = Column(Integer, nullable=False)
    method = Column(String(10), nullable=False, default="CASH")  # CASH | MPESA | CARD

    occurred_at = Column(DateTime, nullable=False, default=utcnow)
    received_at = Column(DateTime, nullable=False, default=utcnow)

    status = Column(String(12), nullable=False, default="RECORDED")  # RECORDED | REVERSED
    integrity_status = Column(String(10), nullable=False, default="OK")  # OK | FLAGGED

    reversal_reason = Column(String(300), nullable=True)
    reversed_at = Column(DateTime, nullable=True)
    reversed_by = Column(Integer, nullable=True)
    raw_details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    shift = relationship("Shift", back_populates="transactions")


class IntegrityFlag(Base):
    """An anomaly detected by validation, ingestion or reconciliation."""

    __tablename__ = "integrity_flags"
    __table_args__ = (
        UniqueConstraint("tenant_id", "dedupe_key", name="uq_flag_dedupe"),
        Index("ix_flag_tenant_status", "tenant_id", "status"),
        Index("ix_flag_tenant_kind", "tenant_id", "kind"),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    kind = Column(String(40), nullable=False)
    severity = Column(String(10), nullable=False, default="MEDIUM")  # HIGH | MEDIUM | LOW
    transaction_id = Column(Integer, ForeignKey("transactions.id"), nullable=True)
    shift_id = Column(Integer, ForeignKey("shifts.id"), nullable=True)
    device_id = Column(String(80), nullable=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=True)
    sequence_no = Column(Integer, nullable=True)
    detail = Column(Text, nullable=False)
    dedupe_key = Column(String(200), nullable=False)

    status = Column(String(15), nullable=False, default="OPEN")  # OPEN | INVESTIGATING | RESOLVED | DISMISSED
    detected_at = Column(DateTime, default=utcnow)
    resolved_by = Column(Integer, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution_note = Column(String(400), nullable=True)


class AuditLog(Base):
    """Append-only, hash-chained record of every state change."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=utcnow)
    tenant_id = Column(Integer, nullable=True)
    actor_id = Column(Integer, nullable=True)
    actor_email = Column(String(150))
    action = Column(String(80), nullable=False)
    entity = Column(String(80), nullable=False)
    entity_id = Column(Integer, nullable=True)
    summary = Column(String(400))
    details = Column(Text, nullable=True)
    prev_hash = Column(String(64), nullable=False, default="")
    hash = Column(String(64), nullable=False)


class ReconciliationRun(Base):
    __tablename__ = "reconciliation_runs"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    run_at = Column(DateTime, default=utcnow)
    summary = Column(Text, nullable=True)
    findings_count = Column(Integer, default=0)
    integrity_score = Column(Integer, default=100)


class IngestBatch(Base):
    __tablename__ = "ingest_batches"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    source = Column(String(12), nullable=False, default="DEVICE")
    device_id = Column(String(80), nullable=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=True)
    reference = Column(String(120), nullable=True)
    record_count = Column(Integer, default=0)
    accepted_count = Column(Integer, default=0)
    duplicate_count = Column(Integer, default=0)
    flagged_count = Column(Integer, default=0)
    gap_count = Column(Integer, default=0)
    received_at = Column(DateTime, default=utcnow)
    note = Column(Text, nullable=True)
