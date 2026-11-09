# FareGuard — Fare Record Integrity Platform

A platform for the **data-integrity problem** in a matatu SACCO's digital fare
collection — not a payment processor. It records and ingests fare transactions,
then guarantees that those records are unique, complete, reconciled and
tamper-evident.

It answers the three failures in the project proposal:

| Documented failure | How FareGuard handles it |
|---|---|
| **Duplicate charges** | Idempotency keys, unique ticket references, unique device sequence numbers, unique provider receipts, and a database-level uniqueness constraint reject duplicates. Near-identical charges within a 5-minute window are raised as `DUPLICATE_FINGERPRINT` anomalies for review. |
| **Missing / disappearing records** | Every record carries a device ID and monotonic sequence number. Ingestion recomputes the expected sequence range and raises `MISSING_RECORD` for any gap. Records are append-only; corrections are reversals, never edits. |
| **Compliance & accountability** | Append-only SHA-256 hash-chained audit log (`GET /api/audit/verify`), role-based access control, tenant isolation, and CSV exports of transactions and anomalies for NTSA-style oversight. |

## What it deliberately does *not* do

It does **not** call M-PESA, Daraja, Pesapal, or any card network. It does not
authorise, capture or settle money. `method` (cash / M-PESA / card) is just a
recorded attribute of a fare, and `provider_receipt` is an optional external
proof reference used for deduplication. There are no `/api/payments` endpoints.

## Run it

```bash
./run.sh          # creates .venv on first run, serves on http://localhost:8000
```

Demo accounts:

| Account | Role | Password |
|---|---|---|
| platform@fareguard.demo | Platform operator (all SACCOs) | admin1234 |
| admin@kiambu.demo | SACCO admin | sacco1234 |
| con@kiambu.demo | Conductor (trip view, shift close) | con12345 |
| auditor@kiambu.demo | Auditor (read-only) | audit1234 |

The demo database is seeded with planted integrity failures: a duplicate charge,
a device sequence gap (missing sequence 3), an underpaid fare, and a cash
variance on a closed shift.

Self-test suite (spawns its own server on port 8032 and exits):

```bash
.venv/bin/python tests/e2e.py
```

## Core workflow

0. **Manage** users, fleet and routes from the **Manage** tab (admins only).
   Platform operators onboard new SACCOs and create SACCO admins; SACCO admins
   add conductors, auditors, vehicles, routes and stage fares. Every change is
   audited.
1. **Ingest** records synced from fare devices or imported from CSV
   (`POST /api/ingest/batch`, `POST /api/ingest/csv`). This is the primary record
   source. Sequence gaps, duplicate references, duplicate receipts and fare
   deviations are detected automatically.
2. **Record an exceptional fare manually** (`POST /api/transactions`, admins
   only) when a device record is missing or needs correction — vehicle, route,
   stage, passengers, tender. The amount must equal `stage fare x passengers`;
   passenger count cannot exceed vehicle capacity; future timestamps are
   rejected. Conductors do not record fares.
3. **Reconcile** a day (`POST /api/reconcile/run`): cash declared vs recorded per
   closed shift, device sequence gaps, duplicate fingerprints, amount mismatches
   and orphan records. Produces an integrity score.
4. **Review** anomalies (`GET /api/flags`) and resolve or dismiss them with a
   note. Every action is audited.
5. **Verify** the audit chain (`GET /api/audit/verify`) and export evidence.

## Key API surface

- `POST /api/auth/login` — JWT (PBKDF2-hashed passwords, HS256)
- `POST /api/transactions` (manual entry, admins only), `GET /api/transactions`, `POST /api/transactions/{id}/reverse`
- `POST /api/ingest/batch`, `POST /api/ingest/csv`, `GET /api/ingest/batches`
- `POST /api/shifts/open`, `POST /api/shifts/{id}/close`, `GET /api/shifts`
- `POST /api/reconcile/run`, `GET /api/reconcile/runs`
- `GET /api/flags`, `GET /api/flags/summary`, `POST /api/flags/{id}/resolve`
- `GET /api/dashboard/stats`
- `GET /api/audit`, `GET /api/audit/verify`
- `GET /api/export/transactions.csv`, `GET /api/export/flags.csv`

### Administration (SACCO_ADMIN / PLATFORM_ADMIN)

- `POST /api/tenants` — onboard a SACCO (platform only)
- `GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}` — add users,
  change role, reset password, enable/disable. SACCO admins may only create and
  manage conductors and auditors in their own SACCO; platform operators may
  create any role and assign it to a SACCO.
- `GET /api/vehicles`, `POST /api/vehicles`, `PATCH /api/vehicles/{id}` — add or
  edit fleet vehicles, capacity and device/POS IDs. Registration and device ID
  are unique per SACCO.
- `GET /api/routes`, `POST /api/routes`, `PATCH /api/routes/{id}`,
  `POST /api/routes/{id}/stages`, `PATCH /api/stages/{id}` — create routes with
  stage fares, append stages, and adjust fares.
- `GET /api/tenants` — list SACCOs (platform only)

## Data model (integrity-relevant)

- `transactions` — the immutable fare ledger. Unique per tenant on
  `external_ref` (ticket), `idempotency_key`, `(device_id, device_seq)` and
  `provider_receipt`. Reversals change status only; the original row is retained.
- `integrity_flags` — anomalies with kind, severity, status and a `dedupe_key` so
  repeated reconciliation runs do not duplicate the same finding.
- `audit_log` — append-only entries where each row's SHA-256 hash covers the
  previous hash, so any edit breaks verification.
- `reconciliation_runs`, `ingest_batches` — evidence of periodic checks and
  device syncs.

## Stack

FastAPI · SQLAlchemy · SQLite (prototype) · PyJWT · vanilla-JS dashboard.
Money is stored as integer cents.

## Production roadmap

- PostgreSQL with the same unique/partial indexes; transactional ingestion.
- Device SDK / Android conductor client with offline queue and sequence numbers.
- Per-tenant retention policy, backups and AES-256 at rest.
- Scheduled reconciliation and alerting (email/SMS) on HIGH anomalies.
- PDF compliance packs alongside CSV exports.
