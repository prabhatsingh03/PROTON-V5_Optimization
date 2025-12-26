#!/usr/bin/env python3
"""
OTP security test suite for PROTON V5 authentication endpoints.
"""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
import statistics
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

import requests


DB_PATH = Path("primary.db")


@dataclass
class OtpScenarioResult:
    name: str
    passed: bool
    duration: float
    findings: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class OtpSecurityTester:
    def __init__(self, base_url: str, email: str, password: str, test_type: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self.test_type = test_type
        self.session = requests.Session()

    # ------------------------------------------------------------------
    def _post(self, endpoint: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}{endpoint}"
        return self.session.post(url, json=payload, timeout=30)

    @staticmethod
    def _query_user(email: str) -> Optional[sqlite3.Row]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT id, email, otp_code, otp_attempts, otp_expires_at, otp_verified "
                "FROM users WHERE email = ?",
                (email,),
            )
            return cur.fetchone()
        finally:
            conn.close()

    @staticmethod
    def _query_audit(action: str) -> List[sqlite3.Row]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT id, action, details, created_at FROM audit_logs "
                "WHERE action = ? ORDER BY id DESC LIMIT 10",
                (action,),
            )
            return cur.fetchall()
        finally:
            conn.close()

    @staticmethod
    def _generic_login_payload(email: str, password: str) -> Dict[str, Any]:
        return {"type": "admin", "email": email, "password": password}

    def _trigger_otp(self) -> requests.Response:
        payload = self._generic_login_payload(self.email, self.password)
        return self._post("/api/login", payload)

    def _verify_otp(self, otp_code: str) -> requests.Response:
        return self._post("/api/auth/verify-otp", {"email": self.email, "otp_code": otp_code})

    # ------------------------------------------------------------------
    def scenario_brute_force(self) -> OtpScenarioResult:
        start = time.time()
        lockout_detected = False
        rate_limit_hits = 0
        guesses = 1000
        status_counter = Counter()
        self._trigger_otp()

        for attempt in range(guesses):
            code = f"{attempt:06d}"
            resp = self._verify_otp(code)
            status_counter[resp.status_code] += 1
            if resp.status_code == 423 or "locked" in resp.text.lower():
                lockout_detected = True
                break
            if resp.status_code == 429:
                rate_limit_hits += 1
                time.sleep(0.2)

        duration = time.time() - start
        user_row = self._query_user(self.email)
        findings = {
            "attempts_made": attempt + 1,
            "status_codes": dict(status_counter),
            "rate_limit_hits": rate_limit_hits,
            "otp_attempts": dict(user_row) if user_row else {},
            "audit_otp_failures": [dict(row) for row in self._query_audit("otp_verification_failed")],
        }
        passed = lockout_detected and rate_limit_hits > 0
        errors: List[str] = []
        if not lockout_detected:
            errors.append("Account lockout not observed within 5 failed attempts.")
        if rate_limit_hits == 0:
            errors.append("Rate limiting not triggered despite rapid attempts.")
        return OtpScenarioResult("brute_force", passed, duration, findings, errors)

    def scenario_replay(self) -> OtpScenarioResult:
        start = time.time()
        self._trigger_otp()
        user_row = self._query_user(self.email)
        if not user_row or not user_row["otp_code"]:
            raise RuntimeError("Unable to read OTP code from database for replay test.")
        otp_code = user_row["otp_code"]
        first = self._verify_otp(otp_code)
        second = self._verify_otp(otp_code)
        findings = {
            "first_status": first.status_code,
            "second_status": second.status_code,
            "second_body": second.text[:200],
            "audit_entries": [dict(row) for row in self._query_audit("otp_verification_failed")],
        }
        duration = time.time() - start
        passed = first.status_code == 200 and second.status_code in (400, 401, 410, 422)
        errors = []
        if second.status_code == 200:
            errors.append("Replay attempt unexpectedly succeeded.")
        return OtpScenarioResult("replay_attack", passed, duration, findings, errors)

    def scenario_timing(self) -> OtpScenarioResult:
        samples = 20
        valid_times: List[float] = []
        invalid_times: List[float] = []

        # Acquire fresh OTP
        login_resp = self._trigger_otp()
        if login_resp.status_code != 200:
            raise RuntimeError(f"Login failed: {login_resp.text}")
        otp_code = self._query_user(self.email)["otp_code"]

        for _ in range(samples):
            start_valid = time.perf_counter()
            self._verify_otp(otp_code)
            valid_times.append((time.perf_counter() - start_valid) * 1000)
            self._trigger_otp()  # refresh OTP for next iteration
            otp_code = self._query_user(self.email)["otp_code"]

        for _ in range(samples):
            start_invalid = time.perf_counter()
            self._verify_otp(f"{random.randint(0, 999999):06d}")
            invalid_times.append((time.perf_counter() - start_invalid) * 1000)

        diff = abs(statistics.mean(valid_times) - statistics.mean(invalid_times))
        passed = diff < 50
        findings = {
            "valid_ms_avg": statistics.mean(valid_times),
            "invalid_ms_avg": statistics.mean(invalid_times),
            "variance_ms": diff,
        }
        errors = []
        if not passed:
            errors.append(f"Timing variance exceeded threshold: {diff:.2f}ms")
        duration = (sum(valid_times) + sum(invalid_times)) / 1000
        return OtpScenarioResult("timing_attack", passed, duration, findings, errors)

    def scenario_expiry(self) -> OtpScenarioResult:
        start = time.time()
        self._trigger_otp()
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "UPDATE users SET otp_expires_at = datetime('now', '-15 minutes') WHERE email = ?",
                (self.email,),
            )
            conn.commit()
        finally:
            conn.close()
        otp_code = self._query_user(self.email)["otp_code"]
        resp = self._verify_otp(otp_code)
        duration = time.time() - start
        passed = resp.status_code in (400, 410, 422)
        findings = {"response": resp.text[:200], "status": resp.status_code}
        errors = []
        if passed is False:
            errors.append("Expired OTP accepted by server.")
        return OtpScenarioResult("otp_expiry", passed, duration, findings, errors)

    def scenario_concurrent_requests(self) -> OtpScenarioResult:
        self._trigger_otp()
        otp_code = self._query_user(self.email)["otp_code"]

        def worker() -> int:
            resp = self._verify_otp(otp_code)
            return resp.status_code

        start = time.time()
        with ThreadPoolExecutor() as executor:
            statuses = list(executor.map(lambda _: worker(), range(5)))
        duration = time.time() - start
        successes = statuses.count(200)
        failures = len(statuses) - successes
        passed = successes == 1 and failures >= 4
        findings = {"status_codes": statuses}
        errors = []
        if not passed:
            errors.append("Multiple concurrent OTP submissions succeeded.")
        return OtpScenarioResult("concurrent_requests", passed, duration, findings, errors)

    def scenario_enumeration(self) -> OtpScenarioResult:
        existing_email = self.email
        non_existent = f"doesnotexist_{int(time.time())}@example.com"
        start = time.time()
        resp_existing = self._post(
            "/api/login", self._generic_login_payload(existing_email, self.password)
        )
        time_existing = time.time() - start
        start = time.time()
        resp_fake = self._post(
            "/api/login", self._generic_login_payload(non_existent, self.password)
        )
        time_fake = time.time() - start
        duration = time_existing + time_fake
        passed = abs(time_existing - time_fake) < 0.05 and resp_existing.status_code == resp_fake.status_code
        findings = {
            "existing_status": resp_existing.status_code,
            "fake_status": resp_fake.status_code,
            "existing_time": time_existing,
            "fake_time": time_fake,
        }
        errors = []
        if not passed:
            errors.append("Login response leaked email existence information.")
        return OtpScenarioResult("email_enumeration", passed, duration, findings, errors)

    # ------------------------------------------------------------------
    def run(self) -> List[OtpScenarioResult]:
        scenarios = {
            "brute-force": self.scenario_brute_force,
            "replay": self.scenario_replay,
            "timing": self.scenario_timing,
            "expiry": self.scenario_expiry,
            "concurrent": self.scenario_concurrent_requests,
            "enumeration": self.scenario_enumeration,
        }
        if self.test_type == "all":
            selected = scenarios.values()
        else:
            selected = [scenarios[self.test_type]]

        results = []
        for scenario in selected:
            try:
                result = scenario()
                results.append(result)
                status = "PASS" if result.passed else "FAIL"
                print(f"[{status}] {result.name}")
            except Exception as exc:
                results.append(
                    OtpScenarioResult(
                        name=scenario.__name__,
                        passed=False,
                        duration=0.0,
                        errors=[str(exc)],
                    )
                )
                print(f"[FAIL] {scenario.__name__}: {exc}")
        return results


def write_report(results: List[OtpScenarioResult], output: Optional[Path]) -> Dict[str, Any]:
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "scenarios": [
            {
                "name": r.name,
                "passed": r.passed,
                "duration": r.duration,
                "findings": r.findings,
                "errors": r.errors,
            }
            for r in results
        ],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"OTP security report saved to {output}")
    else:
        print(json.dumps(summary, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OTP security testing suite")
    parser.add_argument("--url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--test-type",
        default="all",
        choices=["brute-force", "replay", "timing", "expiry", "concurrent", "enumeration", "all"],
    )
    parser.add_argument("--output", type=Path, help="Optional JSON output path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tester = OtpSecurityTester(args.url, args.email, args.password, args.test_type)
    results = tester.run()
    write_report(results, args.output)


if __name__ == "__main__":
    main()


