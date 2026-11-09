"""Seed a demo SACCO with deliberately planted integrity failures."""

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import integrity
from .audit import log_audit
from .models import Route, Shift, Stage, Tenant, User, Vehicle, utcnow
from .security import (
    ROLE_AUDITOR,
    ROLE_CONDUCTOR,
    ROLE_PLATFORM,
    ROLE_SACCO,
    hash_password,
)
from .services import reconciliation

STAGES = [
    ("Kiambu Town", 0, 0),
    ("Ruiru", 1, 4000),
    ("Kahawa West", 2, 7000),
    ("Kasarani", 3, 9000),
    ("Thika Road", 4, 10000),
    ("Nairobi CBD", 5, 15000),
]


def seed(db: Session) -> dict:
    if db.query(Tenant).count() > 0:
        return {"seeded": False}

    tenant = Tenant(
        name="Kiambu Matatu SACCO Ltd",
        region="Kiambu County",
        contact_email="secretary@kiambu-sacco.co.ke",
    )
    db.add(tenant)
    db.flush()

    platform = User(
        tenant_id=None, email="platform@fareguard.demo",
        password_hash=hash_password("admin1234"),
        full_name="Platform Operator", role=ROLE_PLATFORM,
    )
    admin = User(
        tenant_id=tenant.id, email="admin@kiambu.demo",
        password_hash=hash_password("sacco1234"),
        full_name="Margaret Wanjiku", role=ROLE_SACCO,
    )
    conductor = User(
        tenant_id=tenant.id, email="con@kiambu.demo",
        password_hash=hash_password("con12345"),
        full_name="Peter Kamau", role=ROLE_CONDUCTOR,
    )
    conductor2 = User(
        tenant_id=tenant.id, email="con2@kiambu.demo",
        password_hash=hash_password("con12345"),
        full_name="Grace Nyambura", role=ROLE_CONDUCTOR,
    )
    auditor = User(
        tenant_id=tenant.id, email="auditor@kiambu.demo",
        password_hash=hash_password("audit1234"),
        full_name="NTSA Auditor", role=ROLE_AUDITOR,
    )
    db.add_all([platform, admin, conductor, conductor2, auditor])
    db.flush()

    v1 = Vehicle(tenant_id=tenant.id, reg_no="KDD 123A", capacity=14,
                 device_id="DEV-KDD123A")
    v2 = Vehicle(tenant_id=tenant.id, reg_no="KDG 406B", capacity=14,
                 device_id="DEV-KDG406B")
    db.add_all([v1, v2])
    db.flush()

    route = Route(tenant_id=tenant.id, name="Kiambu Town - Nairobi CBD")
    db.add(route)
    db.flush()
    for name, order, fare in STAGES:
        db.add(Stage(route_id=route.id, name=name, order=order,
                     fare_cents=fare))
    db.flush()
    stages = db.query(Stage).order_by(Stage.order).all()

    now = utcnow()
    yesterday = now - timedelta(days=1)

    def bucket_start(moment: datetime) -> datetime:
        return moment.replace(
            minute=moment.minute - (moment.minute % 5),
            second=0, microsecond=0,
        )

    shift_open = Shift(
        tenant_id=tenant.id, vehicle_id=v1.id, conductor_id=conductor.id,
        opened_at=now - timedelta(hours=6),
        status="OPEN",
    )
    shift_closed = Shift(
        tenant_id=tenant.id, vehicle_id=v2.id, conductor_id=conductor2.id,
        opened_at=yesterday.replace(hour=6, minute=0, second=0, microsecond=0),
        closed_at=yesterday.replace(hour=18, minute=0, second=0, microsecond=0),
        declared_cash_cents=50000,
        status="CLOSED",
    )
    db.add_all([shift_open, shift_closed])
    db.flush()

    def at(day: datetime, hour: int, minute: int) -> datetime:
        return day.replace(hour=hour, minute=minute, second=0, microsecond=0)

    def record(**kwargs):
        return integrity.record_transaction(db, tenant_id=tenant.id, **kwargs)

    # Healthy records on today's open shift.
    record(
        source="WEB", vehicle_id=v1.id, stage_id=stages[2].id,
        conductor_id=conductor.id, shift_id=shift_open.id,
        passenger_count=1, amount_cents=stages[2].fare_cents, method="CASH",
        occurred_at=now - timedelta(hours=5, minutes=3), external_ref="TKT-T-001",
        idempotency_key="seed-t-001",
    )
    record(
        source="WEB", vehicle_id=v1.id, stage_id=stages[2].id,
        conductor_id=conductor.id, shift_id=shift_open.id,
        passenger_count=1, amount_cents=stages[2].fare_cents, method="CASH",
        occurred_at=now - timedelta(hours=4, minutes=55), external_ref="TKT-T-002",
        idempotency_key="seed-t-002",
    )
    record(
        source="WEB", vehicle_id=v1.id, stage_id=stages[4].id,
        conductor_id=conductor.id, shift_id=shift_open.id,
        passenger_count=1, amount_cents=stages[4].fare_cents, method="CASH",
        occurred_at=now - timedelta(hours=4, minutes=40), external_ref="TKT-T-003",
        idempotency_key="seed-t-003",
    )
    record(
        source="WEB", vehicle_id=v1.id, stage_id=stages[5].id,
        conductor_id=conductor.id, shift_id=shift_open.id,
        passenger_count=1, amount_cents=stages[5].fare_cents, method="MPESA",
        occurred_at=now - timedelta(hours=4), external_ref="TKT-T-004",
        idempotency_key="seed-t-004", provider_receipt="RKT7A1XQLQ",
    )
    record(
        source="WEB", vehicle_id=v1.id, stage_id=stages[5].id,
        conductor_id=conductor.id, shift_id=shift_open.id,
        passenger_count=1, amount_cents=stages[5].fare_cents, method="CARD",
        occurred_at=now - timedelta(hours=3), external_ref="TKT-T-005",
        idempotency_key="seed-t-005", provider_receipt="AUTH7788",
    )

    # Planted suspected duplicate charge: same trip, two minutes apart.
    record(
        source="WEB", vehicle_id=v1.id, stage_id=stages[4].id,
        conductor_id=conductor.id, shift_id=shift_open.id,
        passenger_count=1, amount_cents=stages[4].fare_cents, method="CASH",
        occurred_at=bucket_start(now - timedelta(hours=2)), external_ref="TKT-DUP-1",
        idempotency_key="seed-dup-1",
    )
    record(
        source="WEB", vehicle_id=v1.id, stage_id=stages[4].id,
        conductor_id=conductor.id, shift_id=shift_open.id,
        passenger_count=1, amount_cents=stages[4].fare_cents, method="CASH",
        occurred_at=bucket_start(now - timedelta(hours=2)) + timedelta(minutes=2), external_ref="TKT-DUP-2",
        idempotency_key="seed-dup-2",
    )

    # Device sync from yesterday: sequence 3 never arrived (missing record).
    device_records = [
        ("KDG-0001", 1, stages[1].id, 4000, "CASH", at(yesterday, 8, 0)),
        ("KDG-0002", 2, stages[1].id, 4000, "CASH", at(yesterday, 8, 12)),
        ("KDG-0004", 4, stages[2].id, 7000, "CASH", at(yesterday, 9, 0)),
        ("KDG-0005", 5, stages[2].id, 7000, "CASH", at(yesterday, 9, 20)),
        # Amount below the expected fare for this stage -> flagged.
        ("KDG-0006", 6, stages[1].id, 3000, "CASH", at(yesterday, 11, 0)),
    ]
    for ref, seq, stage_id, amount, method, when in device_records:
        record(
            source="DEVICE", vehicle_id=v2.id, stage_id=stage_id,
            conductor_id=conductor2.id, shift_id=shift_closed.id,
            passenger_count=1, amount_cents=amount, method=method,
            occurred_at=when, external_ref=ref, idempotency_key=f"seed-{ref}",
            device_id="DEV-KDG406B", device_seq=seq, strict_fare=False,
        )

    integrity.recompute_device_gaps(db, tenant.id, "DEV-KDG406B")

    log_audit(
        db, tenant_id=tenant.id, actor_id=admin.id, actor_email=admin.email,
        action="SEED_DEMO_DATA", entity="tenant", entity_id=tenant.id,
        summary="Seeded demo SACCO with planted integrity failures",
        details={"tenant": tenant.name},
    )
    db.commit()

    reconciliation.run_reconciliation(
        db, tenant, yesterday, actor_id=admin.id, actor_email=admin.email)
    reconciliation.run_reconciliation(
        db, tenant, now, actor_id=admin.id, actor_email=admin.email)
    db.commit()

    return {"seeded": True}
