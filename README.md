# FareGuard — Fare Record Integrity Platform

A platform for the **data-integrity problem** in a matatu SACCO's digital fare
collection — not a payment processor. It records and ingests fare transactions,
then guarantees that those records are unique, complete, reconciled and
tamper-evident.

It answers the failures in the project proposal:

| Documented failure | How FareGuard handles it |
|---|---|
| **Duplicate charges** | Idempotency keys, unique ticket references, unique device sequence numbers, unique provider receipts, and a database-level uniqueness constraint reject duplicates. Near-identical charges within a 5-minute window are raised as `DUPLICATE_FINGERPRINT` anomalies for review. |
| **Missing / disappearing records** | Ingestion recomputes the expected device sequence range and raises `MISSING_RECORD` for any gap. Records are append-only; corrections are reversals, never edits. |
| **Unreported cash** | Every vehicle gets a standing daily target, set once and reused until an admin changes it. Each daily collection snapshots the target; the conductor declares what they collected, then a SACCO admin logs the cash actually counted. Differences raise `DECLARATION_MISMATCH` / `TARGET_MISMATCH` and feed the integrity score. Conductors cannot set targets or log their own handover. |
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
| con@kiambu.demo | Conductor (record fares, own history, declare daily cash) | con12345 |
| auditor@kiambu.demo | Auditor (read-only) | audit1234 |

Seeding creates only the demo accounts, fleet and routes. It does not create
sample transactions, integrity flags or reconciliation runs; record your own data
through the dashboard or APIs.

Self-test suite (spawns its own server on port 8032 and exits):

```bash
.venv/bin/python tests/e2e.py
```

## Deploy to Vercel

Import this repository into Vercel. The Python function entrypoint is
`api/index.py` (Mangum wraps the FastAPI app). Set these environment variables
in the Vercel project:

- `DATABASE_URL` — a pooled Postgres connection string, e.g. Neon or Supabase.
  The app creates tables, applies small column migrations and seeds the demo
  SACCO accounts, fleet and routes on first use (no sample data or anomalies).
- `FAREGUARD_SECRET` — a long random secret used to sign JWTs.

Without `DATABASE_URL` the code still uses local SQLite, but Vercel's filesystem
is ephemeral, so that mode is only suitable for local development and tests.

## Core workflow

0. **Manage** users, fleet and routes from the **Manage** tab (admins only).
   Platform operators onboard new SACCOs and create SACCO admins; SACCO admins
   add conductors, auditors, vehicles, routes and stage fares. Every change is
   audited.
1. **Set a standing target** from the **Daily targets** tab (admins only):
   vehicle and amount due. It applies every day until an admin changes it. For a
   given day, the conductor opens a collection (`POST /api/daily-collections`)
   and declares what they collected (`POST /api/targets/{id}/declare`); the
   collection snapshots the target current at that moment. At handover, the
   admin records the counted cash (`POST /api/targets/{id}/handover`). A shortfall
   or surplus against the snapshot raises `TARGET_MISMATCH`; a difference from
   the conductor's declaration raises `DECLARATION_MISMATCH`. Conductors cannot
   set targets or log handovers.
2. **Record a trip** (`POST /api/transactions`) from the trip screen — vehicle,
   route, stage, total fare collected and tender. One record represents one
   trip, not an individual passenger; the trip total must be greater than zero
   and future timestamps are rejected. Conductors can record their own trips and
   see only their own transaction history; admins can record on any trip. Trip
   totals are self-reported and are not treated as proof of cash; the target
   handover is the independent check.
3. **Reconcile** a day (`POST /api/reconcile/run`): daily target handovers,
   conductor declarations vs counted cash, cash declared vs recorded per closed
   shift, device sequence gaps, duplicate fingerprints, amount mismatches and
   orphan records. Produces an integrity score.
4. **Review** anomalies (`GET /api/flags`) and resolve or dismiss them with a
   note. Every action is audited.
5. **Verify** the audit chain (`GET /api/audit/verify`) and export evidence.

## Key API surface

- `POST /api/auth/login` — JWT (PBKDF2-hashed passwords, HS256)
- `POST /api/transactions` (conductors record their own; admins any trip), `GET /api/transactions` (conductors see only their own), `GET /api/transactions/{id}`, `POST /api/transactions/{id}/reverse`
- `GET /api/targets`, `POST /api/targets` — standing daily target per vehicle (admin sets/changes it)
- `POST /api/daily-collections`, `POST /api/targets/{id}/declare`, `POST /api/targets/{id}/handover` — daily collections, conductor declarations and admin-logged handovers
- `GET /api/reports/sales`, `GET /api/export/sales.csv` — daily collections by vehicle, route and conductor
- `POST /api/shifts/open`, `POST /api/shifts/{id}/close`, `GET /api/shifts`
- `POST /api/reconcile/run`, `GET /api/reconcile/runs`
- `GET /api/flags`, `GET /api/flags/summary`, `POST /api/flags/{id}/resolve`
- `GET /api/dashboard/stats`
- `GET /api/audit`, `GET /api/audit/verify`
- `GET /api/export/transactions.csv`, `GET /api/export/flags.csv`

The device/CSV batch endpoints (`POST /api/ingest/batch`, `POST /api/ingest/csv`,
`GET /api/ingest/batches`) remain available via API but are no longer exposed in
the dashboard. Shifts can only be closed by admins.

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
- `vehicles.daily_target_cents` — the current standing target for a vehicle,
  reused each day until an admin changes it.
- `daily_targets` — one collection per tenant/vehicle/day with the target
  snapshot, conductor's declaration, admin-logged handover, differences and
  `PENDING|MET|SHORT|OVER` status.
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
