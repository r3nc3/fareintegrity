"""End-to-end tests for FareGuard's integrity guarantees.

Exercises the real HTTP API and asserts:
  1. duplicate charges are prevented (idempotency, ticket, device seq, receipt)
  2. fare / capacity validation rejects bad records
  3. suspected duplicate fingerprints are flagged for review
  4. device sequence gaps are detected (missing / disappearing records)
  5. reconciliation catches cash variances and amount mismatches
  6. the audit chain is append-only and tamper-evident
  7. tenant isolation and role enforcement
  8. the platform is NOT a payment processor (no payment endpoints)

Usage:  .venv/bin/python tests/e2e.py
"""

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_DB = ROOT / "data" / "test_fareguard.db"
os.environ["FAREGUARD_DB"] = str(TEST_DB)
sys.path.insert(0, str(ROOT))

for suffix in ("", "-wal", "-shm"):
    path = Path(str(TEST_DB) + suffix)
    if path.exists():
        path.unlink()

BASE = "http://127.0.0.1:8032"


def _start_server():
    import uvicorn
    from app.main import app

    config = uvicorn.Config(app, host="127.0.0.1", port=8032, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(150):
        try:
            urllib.request.urlopen(BASE + "/", timeout=1)
            return server
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("server did not start")


def api(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=15) as res:
            raw = res.read().decode()
            return res.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = raw
        return exc.code, payload


def get_text(path, token):
    req = urllib.request.Request(BASE + path)
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=15) as res:
        return res.read().decode()


def login(email, password):
    code, data = api("POST", "/api/auth/login", {"email": email, "password": password})
    assert code == 200, f"login failed: {data}"
    return data["token"]


def iso(moment):
    return moment.isoformat(timespec="seconds")


def bucket_start(moment):
    return moment.replace(minute=moment.minute - (moment.minute % 5),
                          second=0, microsecond=0)


class Suite:
    def __init__(self):
        self.n = 0
        self.failed = 0
        self.token = None
        self.stage = {}
        self.now = datetime.now(timezone.utc).replace(tzinfo=None)
        self.today = self.now.date()

    def check(self, name, ok, detail=""):
        self.n += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  <- {detail}" if detail and not ok else ""))
        if not ok:
            self.failed += 1

    def run_all(self):
        _start_server()
        self.token = login("admin@kiambu.demo", "sacco1234")

        _, routes = api("GET", "/api/routes", token=self.token)
        self.stage = {s["name"]: s for r in routes for s in r["stages"]}
        _, vehicles = api("GET", "/api/vehicles", token=self.token)
        capacity = vehicles[0]["capacity"]
        thika = self.stage["Thika Road"]

        base = {
            "vehicle_id": 1, "route_id": 1, "stage_id": thika["id"],
            "passenger_count": 1, "amount_cents": thika["fare_cents"],
            "method": "CASH", "idempotency_key": "e2e-1",
            "external_ref": "E2E-TKT-1",
        }

        # --- 1. validation + duplicate prevention -------------------------
        code, tx = api("POST", "/api/transactions", base, self.token)
        self.check("valid fare is recorded", code == 200 and tx["status"] == "RECORDED",
                   str((code, tx)))

        code, dup = api("POST", "/api/transactions", base, self.token)
        self.check(
            "idempotency retry -> 409 with the original record",
            code == 409 and dup.get("error") == "duplicate_idempotency"
            and dup["existing"]["id"] == tx["id"],
            str((code, dup)),
        )

        code, dup = api("POST", "/api/transactions",
                        {**base, "idempotency_key": "e2e-2"}, self.token)
        self.check("same ticket reference -> 409 duplicate_ticket",
                   code == 409 and dup.get("error") == "duplicate_ticket",
                   str((code, dup)))

        code, _ = api("POST", "/api/transactions", {
            **base, "idempotency_key": "e2e-3", "external_ref": "E2E-TKT-3",
            "amount_cents": thika["fare_cents"] - 1,
        }, self.token)
        self.check("amount != fare x passengers -> 422", code == 422, str(code))

        code, _ = api("POST", "/api/transactions", {
            **base, "idempotency_key": "e2e-4", "external_ref": "E2E-TKT-4",
            "passenger_count": capacity + 1,
            "amount_cents": thika["fare_cents"] * (capacity + 1),
        }, self.token)
        self.check("passenger count over capacity -> 422", code == 422, str(code))

        seq = {**base, "idempotency_key": "e2e-seq-1",
               "external_ref": "E2E-SEQ-1", "device_id": "E2E-DEV",
               "device_seq": 1}
        code, _ = api("POST", "/api/transactions", seq, self.token)
        code2, err = api("POST", "/api/transactions",
                         {**seq, "idempotency_key": "e2e-seq-2",
                          "external_ref": "E2E-SEQ-2"}, self.token)
        self.check("duplicate device sequence -> 409",
                   code == 200 and code2 == 409
                   and err.get("error") == "duplicate_sequence",
                   str((code, code2, err)))

        receipt = {**base, "idempotency_key": "e2e-rcpt-1",
                   "external_ref": "E2E-RCPT-A", "method": "MPESA",
                   "provider_receipt": "E2E-RECEIPT-X"}
        code, _ = api("POST", "/api/transactions", receipt, self.token)
        code2, err = api("POST", "/api/transactions",
                         {**receipt, "idempotency_key": "e2e-rcpt-2",
                          "external_ref": "E2E-RCPT-B"}, self.token)
        self.check("duplicate provider receipt -> 409",
                   code == 200 and code2 == 409
                   and err.get("error") == "duplicate_receipt",
                   str((code, code2, err)))

        # --- 2. soft duplicate fingerprint ---------------------------------
        kasarani = self.stage["Kasarani"]
        first_time = bucket_start(self.now - timedelta(hours=2))
        fp_base = {
            "vehicle_id": 1, "route_id": 1, "stage_id": kasarani["id"],
            "passenger_count": 1, "amount_cents": kasarani["fare_cents"],
            "method": "CASH",
        }
        code, fp1 = api("POST", "/api/transactions", {
            **fp_base, "occurred_at": iso(first_time),
            "external_ref": "E2E-FP-1", "idempotency_key": "e2e-fp-1",
        }, self.token)
        code2, fp2 = api("POST", "/api/transactions", {
            **fp_base, "occurred_at": iso(first_time + timedelta(minutes=2)),
            "external_ref": "E2E-FP-2", "idempotency_key": "e2e-fp-2",
        }, self.token)
        self.check("near-identical charge is flagged, not silently accepted",
                   code == 200 and code2 == 200
                   and fp1["integrity_status"] == "OK"
                   and fp2["integrity_status"] == "FLAGGED",
                   str((fp1.get("integrity_status"), fp2.get("integrity_status"))))

        _, fp_flags = api("GET", "/api/flags?kind=DUPLICATE_FINGERPRINT&limit=200",
                          token=self.token)
        self.check("duplicate-fingerprint anomaly is raised",
                   any(f["transaction_id"] == fp2["id"] for f in fp_flags),
                   str(fp_flags))

        # --- 3. device ingestion + sequence gaps ---------------------------
        ruiru = self.stage["Ruiru"]
        kahawa = self.stage["Kahawa West"]
        ingest_time = self.now - timedelta(hours=3)
        records = [
            {"external_ref": "ING-1", "device_seq": 1, "stage_id": ruiru["id"],
             "passenger_count": 1, "amount_cents": ruiru["fare_cents"],
             "method": "CASH", "occurred_at": iso(ingest_time)},
            {"external_ref": "ING-2", "device_seq": 2, "stage_id": ruiru["id"],
             "passenger_count": 1, "amount_cents": ruiru["fare_cents"],
             "method": "CASH", "occurred_at": iso(ingest_time + timedelta(minutes=10))},
            {"external_ref": "ING-4", "device_seq": 4, "stage_id": kahawa["id"],
             "passenger_count": 1, "amount_cents": kahawa["fare_cents"],
             "method": "CASH", "occurred_at": iso(ingest_time + timedelta(minutes=20))},
            {"external_ref": "ING-5", "device_seq": 5, "stage_id": kahawa["id"],
             "passenger_count": 1, "amount_cents": kahawa["fare_cents"],
             "method": "CASH", "occurred_at": iso(ingest_time + timedelta(minutes=30))},
        ]
        batch = {"source": "DEVICE", "device_id": "E2E-INGEST-DEV",
                 "vehicle_id": 1, "records": records}
        code, result = api("POST", "/api/ingest/batch", batch, self.token)
        self.check("device batch ingested and gap detected",
                   code == 200 and result["accepted_count"] == 4
                   and result["missing_sequences"] == [3],
                   str((code, result)))

        code, result2 = api("POST", "/api/ingest/batch", batch, self.token)
        self.check("replayed batch is idempotent (no new records)",
                   code == 200 and result2["accepted_count"] == 0
                   and result2["duplicate_count"] == 4,
                   str((code, result2)))

        mismatch = {
            "source": "DEVICE", "device_id": "E2E-INGEST-DEV", "vehicle_id": 1,
            "records": [{
                "external_ref": "ING-6", "device_seq": 6,
                "stage_id": ruiru["id"], "passenger_count": 1,
                "amount_cents": ruiru["fare_cents"] - 1000,
                "method": "CASH",
                "occurred_at": iso(ingest_time + timedelta(minutes=40)),
            }],
        }
        code, result3 = api("POST", "/api/ingest/batch", mismatch, self.token)
        self.check("ingested underpayment is accepted but flagged",
                   code == 200 and result3["accepted_count"] == 1
                   and result3["flagged_count"] == 1,
                   str((code, result3)))

        _, gap_flags = api("GET", "/api/flags?kind=MISSING_RECORD&limit=200",
                           token=self.token)
        gap = next((f for f in gap_flags
                    if f["device_id"] == "E2E-INGEST-DEV"
                    and f["sequence_no"] == 3), None)
        self.check("missing sequence 3 appears as a HIGH anomaly",
                   gap is not None and gap["severity"] == "HIGH", str(gap))

        _, amount_flags = api("GET", "/api/flags?kind=AMOUNT_MISMATCH&limit=200",
                              token=self.token)
        self.check("amount mismatch anomaly is raised", len(amount_flags) >= 1)

        # --- 4. reconciliation --------------------------------------------
        yesterday = (self.today - timedelta(days=1)).isoformat()
        code, run = api("POST", "/api/reconcile/run", {"day": yesterday}, self.token)
        _, cash_flags = api("GET", "/api/flags?kind=CASH_MISMATCH&limit=200",
                            token=self.token)
        self.check("reconciliation flags the seeded cash variance",
                   code == 200 and run["summary"]["cash_mismatches"] >= 1
                   and len(cash_flags) >= 1,
                   str((code, run.get("summary"))))

        code, run_today = api("POST", "/api/reconcile/run",
                              {"day": self.today.isoformat()}, self.token)
        self.check("reconciliation runs for today",
                   code == 200 and "transaction_count" in run_today["summary"],
                   str((code, run_today)))

        # --- 5. reversal keeps the original row ----------------------------
        code, reversed_tx = api("POST", f"/api/transactions/{tx['id']}/reverse",
                                {"reason": "e2e reversal"}, self.token)
        _, still_there = api("GET", f"/api/transactions/{tx['id']}",
                             token=self.token)
        self.check("reversal retains the original record",
                   code == 200 and reversed_tx["status"] == "REVERSED"
                   and still_there["external_ref"] == "E2E-TKT-1",
                   str((code, reversed_tx.get("status"))))

        _, audit = api("GET", "/api/audit?limit=400", token=self.token)
        self.check("reversal is recorded in the audit trail",
                   any(e["action"] == "TRANSACTION_REVERSED" for e in audit))

        # --- 6. CSV import + exports --------------------------------------
        csv_text = (
            "external_ref,device_seq,stage,passenger_count,amount,method,occurred_at\n"
            f"CSV-E2E-1,1,Ruiru,1,40,CASH,{iso(self.now - timedelta(hours=4))}\n"
            f"CSV-E2E-2,2,Kahawa West,1,70,CASH,"
            f"{iso(self.now - timedelta(hours=4) + timedelta(minutes=10))}"
        )
        code, csv_result = api("POST", "/api/ingest/csv", {
            "source": "CSV", "device_id": "E2E-CSV-DEV",
            "vehicle_id": 1, "csv": csv_text,
        }, self.token)
        self.check("CSV import accepts valid records",
                   code == 200 and csv_result["accepted_count"] == 2,
                   str((code, csv_result)))

        tx_csv = get_text("/api/export/transactions.csv", self.token)
        flag_csv = get_text("/api/export/flags.csv", self.token)
        self.check("transaction export is CSV",
                   tx_csv.startswith("id,tenant_id") and "E2E-TKT-1" in tx_csv)
        self.check("anomaly export is CSV",
                   flag_csv.startswith("id,tenant_id") and "MISSING_RECORD" in flag_csv)

        # --- 7. anomaly workflow ------------------------------------------
        code, resolved = api("POST", f"/api/flags/{gap['id']}/resolve",
                             {"status": "RESOLVED", "note": "e2e review"},
                             self.token)
        self.check("anomaly can be resolved with a note",
                   code == 200 and resolved["status"] == "RESOLVED",
                   str((code, resolved)))

        # --- 8. roles / tenant isolation / not-a-payment-platform ----------
        code, _ = api("GET", "/api/payments", token=self.token)
        self.check("there is no payment-processing endpoint", code == 404, str(code))

        platform_token = login("platform@fareguard.demo", "admin1234")
        _, tenants = api("GET", "/api/tenants", token=platform_token)
        self.check("platform operator sees tenants", len(tenants) >= 1)

        _, mine = api("GET", "/api/vehicles", token=self.token)
        self.check("tenant user only sees own vehicles",
                   all(v["tenant_id"] == 1 for v in mine))

        auditor_token = login("auditor@kiambu.demo", "audit1234")
        code, _ = api("POST", "/api/transactions",
                      {**base, "idempotency_key": "e2e-audit",
                       "external_ref": "E2E-AUDIT"}, auditor_token)
        self.check("auditor is read-only (cannot record fares)", code == 403, str(code))

        # --- 9. audit chain integrity (tamper test last) -------------------
        _, verify = api("GET", "/api/audit/verify", token=self.token)
        self.check("audit chain verifies clean", verify.get("ok") is True, str(verify))

        from app.db import SessionLocal
        from app.models import AuditLog

        with SessionLocal() as db:
            row = db.query(AuditLog).filter(AuditLog.action == "LOGIN").first()
            row.summary = (row.summary or "") + " (tampered)"
            db.commit()

        _, verify2 = api("GET", "/api/audit/verify", token=self.token)
        self.check("tampered audit row is detected", verify2.get("ok") is False,
                   str(verify2))

        print(f"\n{self.n} checks, {self.failed} failed")
        return 1 if self.failed else 0


if __name__ == "__main__":
    sys.exit(Suite().run_all())
