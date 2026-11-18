"""Seed a demo SACCO with accounts, fleet and routes."""

from sqlalchemy.orm import Session

from .audit import log_audit
from .models import Route, Stage, Tenant, User, Vehicle
from .security import (
    ROLE_AUDITOR,
    ROLE_CONDUCTOR,
    ROLE_PLATFORM,
    ROLE_SACCO,
    hash_password,
)

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

    log_audit(
        db, tenant_id=tenant.id, actor_id=admin.id, actor_email=admin.email,
        action="SEED_DEMO_DATA", entity="tenant", entity_id=tenant.id,
        summary="Seeded demo SACCO with accounts, fleet and routes",
        details={"tenant": tenant.name},
    )
    db.commit()

    return {"seeded": True}
