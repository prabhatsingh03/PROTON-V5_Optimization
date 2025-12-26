#!/usr/bin/env python3
"""
Payment idempotency and concurrency test suite for PROTON V5.

Scenarios:
    * Rapid sequential upgrade clicks
    * Concurrent upgrade requests (default 100 threads)
    * Duplicate idempotency key replay
    * Pending subscription guard enforcement
    * Database race condition verification
    * Frontend button state validation

The script authenticates via the OTP-enabled `/api/login` flow by reusing
`get_auth_token` from `load_test.py`.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from load_test import get_auth_token


DB_PATH = Path("primary.db")
AUDIT_QUERY = """
    SELECT id, action, details, created_at
    FROM audit_logs
    WHERE action LIKE 'payment_request%'
    ORDER BY id DESC LIMIT 50
"""


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    duration: float
    status_codes: Dict[int, int] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class PaymentIdempotencyTester:
    def __init__(
        self,
        base_url: str,
        email: str,
        password: str,
        otp: Optional[str],
        threads: int,
        plan_type: str,
        billing_cycle: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self.otp = otp
        self.threads = threads
        self.plan_type = plan_type
        self.billing_cycle = billing_cycle
        self.auth_token: Optional[str] = None
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self.results: List[ScenarioResult] = []

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def authenticate(self) -> None:
        token = get_auth_token(self.base_url, self.email, self.password, self.otp)
        if not token:
            raise RuntimeError("Authentication failed; cannot execute payment tests.")
        self.auth_token = token
        self.session.headers["Authorization"] = f"Bearer {token}"

    def _upgrade(self, request_id: Optional[str] = None) -> requests.Response:
        payload = {
            "plan_type": self.plan_type,
            "billing_cycle": self.billing_cycle,
            "request_id": request_id or str(uuid.uuid4()),
        }
        url = f"{self.base_url}/api/org/subscription/upgrade"
        return self.session.post(url, json=payload, timeout=30)

    def _record_status_code(
        self, codes: Dict[int, int], response: requests.Response
    ) -> None:
        with self.lock:
            codes[response.status_code] = codes.get(response.status_code, 0) + 1

    def _query_db(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(query, params)
            return cur.fetchall()
        finally:
            conn.close()

    def _current_payment_state(self) -> Dict[str, Any]:
        payment_rows = self._query_db(
            "SELECT org_id, request_id, status, created_at "
            "FROM payment_requests "
            "ORDER BY id DESC LIMIT 5"
        )
        sub_rows = self._query_db(
            "SELECT org_id, plan_type, status, created_at "
            "FROM subscriptions ORDER BY id DESC LIMIT 5"
        )
        audit_rows = self._query_db(AUDIT_QUERY)
        return {
            "payment_requests": [dict(row) for row in payment_rows],
            "subscriptions": [dict(row) for row in sub_rows],
            "audit_logs": [dict(row) for row in audit_rows],
        }

    # ------------------------------------------------------------------
    # Scenario implementations
    # ------------------------------------------------------------------
    def scenario_rapid_clicks(self) -> ScenarioResult:
        status_codes: Dict[int, int] = {}
        errors: List[str] = []
        start = time.time()
        shared_request_ids: List[str] = []

        for _ in range(10):
            rid = str(uuid.uuid4())
            shared_request_ids.append(rid)
            resp = self._upgrade(request_id=rid)
            self._record_status_code(status_codes, resp)
            if resp.status_code not in (200, 201, 409):
                errors.append(
                    f"Unexpected status {resp.status_code}: {resp.text[:150]}"
                )
            time.sleep(0.08)  # <1 second across 10 clicks

        duration = time.time() - start
        passed = 200 in status_codes and sum(status_codes.values()) == 10
        return ScenarioResult(
            name="rapid_sequential_clicks",
            passed=passed,
            duration=duration,
            status_codes=status_codes,
            details={
                "request_ids": shared_request_ids,
                "payment_state": self._current_payment_state(),
            },
            errors=errors,
        )

    def scenario_concurrent_requests(self) -> ScenarioResult:
        status_codes: Dict[int, int] = {}
        errors: List[str] = []
        start = time.time()
        shared_request_id = str(uuid.uuid4())

        def worker(idx: int) -> Dict[str, Any]:
            rid = shared_request_id if idx % 2 == 0 else str(uuid.uuid4())
            response = self._upgrade(request_id=rid)
            self._record_status_code(status_codes, response)
            body: Dict[str, Any]
            try:
                body = response.json()
            except ValueError:
                body = {"message": response.text[:200]}
            return {
                "status": response.status_code,
                "request_id": rid,
                "body": body,
            }

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            futures = [executor.submit(worker, i) for i in range(self.threads)]
            payloads = [future.result() for future in futures]

        duration = time.time() - start
        success_count = status_codes.get(200, 0) + status_codes.get(201, 0)
        conflict_count = status_codes.get(409, 0)
        passed = success_count == 1 and conflict_count >= self.threads - 1

        return ScenarioResult(
            name="concurrent_requests",
            passed=passed,
            duration=duration,
            status_codes=status_codes,
            details={
                "responses": payloads[:10],  # keep report manageable
                "payment_state": self._current_payment_state(),
            },
            errors=errors,
        )

    def scenario_duplicate_keys(self) -> ScenarioResult:
        status_codes: Dict[int, int] = {}
        errors: List[str] = []
        rid = str(uuid.uuid4())
        start = time.time()

        first = self._upgrade(request_id=rid)
        self._record_status_code(status_codes, first)
        time.sleep(1)
        replay = self._upgrade(request_id=rid)
        self._record_status_code(status_codes, replay)

        duration = time.time() - start
        passed = (
            first.status_code in (200, 201)
            and replay.status_code == 200
            and replay.json().get("request_id") == rid
        )
        if replay.status_code != 200:
            errors.append(f"Replay request failed: {replay.text[:200]}")

        details = {
            "first_response": first.json() if first.ok else first.text[:200],
            "replay_response": replay.json()
            if replay.status_code == 200
            else replay.text[:200],
            "payment_state": self._current_payment_state(),
        }
        return ScenarioResult(
            name="duplicate_idempotency_keys",
            passed=passed,
            duration=duration,
            status_codes=status_codes,
            details=details,
            errors=errors,
        )

    def scenario_pending_guard(self) -> ScenarioResult:
        status_codes: Dict[int, int] = {}
        errors: List[str] = []
        start = time.time()

        # Kick off a request that intentionally sleeps on the server by using
        # unique request id. We simply re-call endpoint quickly to hit guard.
        rid = str(uuid.uuid4())
        first = self._upgrade(request_id=rid)
        self._record_status_code(status_codes, first)
        second = self._upgrade()
        self._record_status_code(status_codes, second)

        duration = time.time() - start
        passed = first.status_code in (200, 201) and second.status_code == 409
        if second.status_code != 409:
            errors.append(f"Pending guard not enforced: {second.text[:200]}")

        return ScenarioResult(
            name="pending_subscription_guard",
            passed=passed,
            duration=duration,
            status_codes=status_codes,
            details={
                "first": first.json() if first.ok else first.text[:200],
                "second": second.json()
                if second.status_code == 409
                else second.text[:200],
                "payment_state": self._current_payment_state(),
            },
            errors=errors,
        )

    def scenario_db_race(self) -> ScenarioResult:
        start = time.time()
        subs = self._query_db(
            "SELECT org_id, COUNT(*) AS c FROM subscriptions "
            "WHERE status IN ('created','active') "
            "GROUP BY org_id HAVING c > 1"
        )
        requests = self._query_db(
            "SELECT org_id, COUNT(*) AS c FROM payment_requests "
            "GROUP BY org_id HAVING c > 1"
        )
        duration = time.time() - start
        passed = not subs
        details = {
            "duplicate_subscriptions": [dict(row) for row in subs],
            "duplicate_payment_requests": [dict(row) for row in requests],
        }
        errors = []
        if subs:
            errors.append("Duplicate active subscriptions detected.")
        return ScenarioResult(
            name="database_race_conditions",
            passed=passed,
            duration=duration,
            status_codes={},
            details=details,
            errors=errors,
        )

    def scenario_frontend_button(self) -> ScenarioResult:
        start = time.time()
        script_path = Path("static/js/auth.js")
        status_codes: Dict[int, int] = {}
        errors: List[str] = []
        if not script_path.exists():
            errors.append("Frontend script not found at static/js/auth.js")
            return ScenarioResult(
                name="frontend_button_state",
                passed=False,
                duration=0.1,
                status_codes=status_codes,
                details={},
                errors=errors,
            )
        contents = script_path.read_text(encoding="utf-8", errors="ignore")
        required_snippets = ["upgradeButton", "disabled", "spinner"]
        missing = [snippet for snippet in required_snippets if snippet not in contents]
        duration = time.time() - start
        passed = not missing
        if missing:
            errors.append(f"Missing spinner/disable logic markers: {missing}")
        return ScenarioResult(
            name="frontend_button_state",
            passed=passed,
            duration=duration,
            status_codes=status_codes,
            details={"checked_snippets": required_snippets},
            errors=errors,
        )

    # ------------------------------------------------------------------
    def run(self) -> List[ScenarioResult]:
        self.authenticate()
        scenarios = [
            self.scenario_rapid_clicks,
            self.scenario_concurrent_requests,
            self.scenario_duplicate_keys,
            self.scenario_pending_guard,
            self.scenario_db_race,
            self.scenario_frontend_button,
        ]
        for scenario in scenarios:
            try:
                result = scenario()
                self.results.append(result)
                status = "PASS" if result.passed else "FAIL"
                print(f"[{status}] {result.name} ({result.duration:.2f}s)")
            except Exception as exc:  # pragma: no cover - safety net
                result = ScenarioResult(
                    name=scenario.__name__,
                    passed=False,
                    duration=0.0,
                    errors=[f"Unhandled exception: {exc}"],
                )
                self.results.append(result)
                print(f"[FAIL] {scenario.__name__}: {exc}")
        return self.results


def generate_report(results: List[ScenarioResult], output_path: Optional[Path]) -> Dict[str, Any]:
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "results": [
            {
                "name": r.name,
                "passed": r.passed,
                "duration": r.duration,
                "status_codes": r.status_codes,
                "details": r.details,
                "errors": r.errors,
            }
            for r in results
        ],
    }
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Report written to {output_path}")
    else:
        print(json.dumps(summary, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Payment idempotency test suite")
    parser.add_argument("--url", required=True, help="Base URL of the PROTON API")
    parser.add_argument("--email", required=True, help="Org admin email")
    parser.add_argument("--password", required=True, help="Org admin password")
    parser.add_argument("--otp", help="OTP value for non-interactive login")
    parser.add_argument("--threads", type=int, default=100, help="Concurrent threads")
    parser.add_argument("--plan-type", default="plus", help="Plan type to upgrade to")
    parser.add_argument(
        "--billing-cycle",
        default="monthly",
        choices=["monthly", "yearly"],
        help="Billing cycle",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path (default prints to stdout)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tester = PaymentIdempotencyTester(
        base_url=args.url,
        email=args.email,
        password=args.password,
        otp=args.otp,
        threads=args.threads,
        plan_type=args.plan_type,
        billing_cycle=args.billing_cycle,
    )
    results = tester.run()
    generate_report(results, args.output)


if __name__ == "__main__":
    main()



