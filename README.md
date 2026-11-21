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

## Connect Supabase

FareGuard uses Supabase in two independent ways:

| Purpose | Environment variables |
|---|---|
| PostgreSQL data storage | `DATABASE_URL` (or `SUPABASE_DATABASE_URL`) |
| Email signup and login | `SUPABASE_URL` and `SUPABASE_ANON_KEY` |

The service-role key is never used. Leave the Supabase Auth variables unset to
run with local demo accounts only.

### Database

1. In Supabase, open **Project Settings → Database → Connection strings**.
2. For Vercel/serverless deployment, copy the **Transaction pooler** URI. It
   normally uses port `6543` and a host such as
   `aws-0-<region>.pooler.supabase.com`.
3. Replace `[YOUR-PASSWORD]` with the database password. URL-encode special
   characters in the password.
4. Set the URI as `DATABASE_URL` in the app environment. `SUPABASE_DATABASE_URL`
   is also accepted as an alias.
5. Set `FAREGUARD_SECRET` to a long random value used to sign FareGuard JWTs.

The app normalizes Supabase URLs to the `psycopg` driver, adds `sslmode=require`
for Supabase hosts, and uses Non-pooling mode with prepared statements disabled
for transaction pooler URLs. On first use it creates tables, applies small
column migrations and seeds only the demo accounts, fleet and routes.

For a local persistent backend, use the direct or session-pooler URI instead:

```bash
export DATABASE_URL='postgresql://postgres:<url-encoded-password>@db.<project-ref>.supabase.co:5432/postgres'
export FAREGUARD_SECRET='replace-with-a-long-random-secret'
./run.sh
```

### Email signup and login

1. In Supabase, open **Authentication → Providers → Email** and enable email
   signups. Email confirmation can be enabled or disabled; both flows work.
2. In **Project Settings → API**, copy the **Project URL** and the anon /
   publishable key. Do not use the service-role key.
3. Set them as `SUPABASE_URL` and `SUPABASE_ANON_KEY` (`SUPABASE_PUBLISHABLE_KEY`
   is accepted as an alias for the key).
4. Set `FAREGUARD_SECRET` as above; Supabase tokens are exchanged for signed
   FareGuard session tokens after verification.
5. Redeploy Vercel after adding the variables.

When Supabase Auth is configured, the sign-in page shows **Create a SACCO
account**. Signup asks for full name, SACCO name, email and password. FareGuard
stores the SACCO name and full name in Supabase user metadata; on the first
verified sign-in it creates the SACCO tenant and makes that user its
`SACCO_ADMIN`. Role metadata is never accepted from the browser.

If email confirmation is enabled, signup tells the user to check their email;
the FareGuard account is created after they confirm and sign in. If it is
disabled, signup signs the user in immediately. Existing local accounts are not
auto-linked to a Supabase identity, so they cannot be taken over by a matching
email; they continue to work with their existing password. Supabase Auth only
takes over an account once it is linked by `supabase_user_id`.

Example Vercel values:

```text
DATABASE_URL=postgresql://postgres.<project-ref>:<url-encoded-password>@aws-0-<region>.pooler.supabase.com:6543/postgres?pgbouncer=true
FAREGUARD_SECRET=<long-random-secret>
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_ANON_KEY=<anon-or-publishable-key>
```

Never commit the real connection string, keys or secret to Git.

## Deploy to Vercel

Import this repository into Vercel. The Python function entrypoint is
`api/index.py` (Mangum wraps the FastAPI app). Set `DATABASE_URL`,
`FAREGUARD_SECRET`, `SUPABASE_URL` and `SUPABASE_ANON_KEY` as described above.

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

- `GET /api/auth/config` — whether Supabase email signup is enabled
- `POST /api/auth/signup` — Supabase email signup (creates a SACCO tenant and admin)
- `POST /api/auth/login` — Supabase Auth when configured, local PBKDF2 fallback otherwise; returns a signed FareGuard JWT
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

FastAPI · SQLAlchemy · PostgreSQL/Supabase · Supabase Auth · SQLite (local fallback) · PyJWT · vanilla-JS dashboard.
Money is stored as integer cents.

## Production roadmap

- PostgreSQL with the same unique/partial indexes; transactional ingestion.
- Device SDK / Android conductor client with offline queue and sequence numbers.
- Per-tenant retention policy, backups and AES-256 at rest.
- Scheduled reconciliation and alerting (email/SMS) on HIGH anomalies.
- PDF compliance packs alongside CSV exports.
