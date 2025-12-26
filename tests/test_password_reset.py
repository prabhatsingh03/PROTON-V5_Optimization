#!/usr/bin/env python3
"""
Password reset security/regression tests for PROTON V5.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


DB_PATH = Path("primary.db")


@dataclass
class PasswordResetResult:
    name: str
    passed: bool
    duration: float
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class PasswordResetTester:
    def __init__(self, base_url: str, email: str, test_type: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.test_type = test_type
        self.session = requests.Session()

    # ------------------------------------------------------------------
    def _post(self, endpoint: str, payload: Dict[str, Any]) -> requests.Response:
        url = f"{self.base_url}{endpoint}"
        return self.session.post(url, json=payload, timeout=30)

    def _request_reset(self, email: str) -> requests.Response:
        return self._post("/api/auth/forgot-password", {"email": email})

    def _reset_password(self, token: str, new_password: str) -> requests.Response:
        payload = {"reset_token": token, "password": new_password}
        return self._post("/api/auth/reset-password", payload)

    @staticmethod
    def _fetch_user(email: str) -> Optional[sqlite3.Row]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT id, email, reset_token, reset_token_expires_at, status "
                "FROM users WHERE email = ?",
                (email,),
            )
            return cur.fetchone()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    def scenario_token_expiry(self) -> PasswordResetResult:
        start = time.time()
        self._request_reset(self.email)
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "UPDATE users SET reset_token_expires_at = datetime('now', '-2 hours') "
                "WHERE email = ?",
                (self.email,),
            )
            conn.commit()
        finally:
            conn.close()
        row = self._fetch_user(self.email)
        token = row["reset_token"]
        resp = self._reset_password(token, "NewPass123!")
        duration = time.time() - start
        passed = resp.status_code in (400, 410, 422)
        errors = []
        if not passed:
            errors.append("Expired token accepted by reset endpoint.")
        details = {"status": resp.status_code, "response": resp.text[:200]}
        return PasswordResetResult("token_expiry", passed, duration, details, errors)

    def scenario_single_use(self) -> PasswordResetResult:
        start = time.time()
        self._request_reset(self.email)
        token = self._fetch_user(self.email)["reset_token"]
        first = self._reset_password(token, "StrongPass123!")
        second = self._reset_password(token, "AnotherPass123!")
        duration = time.time() - start
        passed = first.status_code == 200 and second.status_code in (400, 401, 410, 422)
        errors = []
        if not passed:
            errors.append("Reset token reused successfully; expected failure.")
        details = {
            "first_status": first.status_code,
            "second_status": second.status_code,
            "second_response": second.text[:200],
        }
        return PasswordResetResult("single_use", passed, duration, details, errors)

    def scenario_rate_limit(self) -> PasswordResetResult:
        start = time.time()
        forgot_statuses = []
        for _ in range(5):
            resp = self._request_reset(self.email)
            forgot_statuses.append(resp.status_code)
            time.sleep(0.5)
        reset_statuses = []
        tokens = []
        for _ in range(5):
            self._request_reset(self.email)
            tokens.append(self._fetch_user(self.email)["reset_token"])
        for token in tokens + tokens[:5]:
            resp = self._reset_password(token, "ResetPass123!")
            reset_statuses.append(resp.status_code)
            time.sleep(0.2)
        duration = time.time() - start
        forgot_limits_hit = any(status == 429 for status in forgot_statuses[3:])
        reset_limits_hit = any(status == 429 for status in reset_statuses[5:])
        passed = forgot_limits_hit and reset_limits_hit
        errors = []
        if not forgot_limits_hit:
            errors.append("Forgot-password endpoint did not enforce hourly limit.")
        if not reset_limits_hit:
            errors.append("Reset-password endpoint did not enforce per-minute limit.")
        details = {
            "forgot_statuses": forgot_statuses,
            "reset_statuses": reset_statuses,
        }
        return PasswordResetResult("rate_limiting", passed, duration, details, errors)

    def scenario_token_security(self) -> PasswordResetResult:
        start = time.time()
        tokens = []
        for _ in range(100):
            resp = self._request_reset(self.email)
            if resp.status_code != 200:
                raise RuntimeError("Unable to request password reset during token security test.")
            token = self._fetch_user(self.email)["reset_token"]
            tokens.append(token)
        unique_tokens = len(set(tokens))
        valid_lengths = all(len(token) >= 43 for token in tokens)
        duration = time.time() - start
        passed = unique_tokens == len(tokens) and valid_lengths
        errors = []
        if unique_tokens != len(tokens):
            errors.append("Duplicate reset tokens detected.")
        if not valid_lengths:
            errors.append("Token length below expected security threshold.")
        details = {
            "unique_tokens": unique_tokens,
            "total_tokens": len(tokens),
            "min_length": min(len(t) for t in tokens),
        }
        return PasswordResetResult("token_security", passed, duration, details, errors)

    def scenario_password_strength(self) -> PasswordResetResult:
        start = time.time()
        self._request_reset(self.email)
        token = self._fetch_user(self.email)["reset_token"]
        weak_passwords = {
            "too_short": "Pass1!",
            "no_upper": "password123!",
            "no_lower": "PASSWORD123!",
            "no_digit": "Password!",
            "no_special": "Password123",
        }
        results = {}
        for label, pwd in weak_passwords.items():
            resp = self._reset_password(token, pwd)
            results[label] = resp.status_code
        duration = time.time() - start
        passed = all(status in (400, 422) for status in results.values())
        errors = []
        if not passed:
            errors.append("Weak password accepted by reset endpoint.")
        details = {"statuses": results}
        return PasswordResetResult("password_strength", passed, duration, details, errors)

    def scenario_enumeration(self) -> PasswordResetResult:
        start = time.time()
        fake_email = f"nonexistent_{int(time.time())}@example.com"
        real_resp = self._request_reset(self.email)
        real_time = time.time() - start
        start = time.time()
        fake_resp = self._request_reset(fake_email)
        fake_time = time.time() - start
        duration = real_time + fake_time
        passed = real_resp.status_code == fake_resp.status_code and abs(real_time - fake_time) < 0.05
        errors = []
        if not passed:
            errors.append("Password reset responses differ between emails.")
        details = {
            "real_status": real_resp.status_code,
            "fake_status": fake_resp.status_code,
            "real_time": real_time,
            "fake_time": fake_time,
        }
        return PasswordResetResult("email_enumeration", passed, duration, details, errors)

    def scenario_user_status(self) -> PasswordResetResult:
        conn = sqlite3.connect(DB_PATH)
        row = self._fetch_user(self.email)
        original_status = row["status"]
        statuses_to_test = ["pending", "suspended"]
        responses = {}
        try:
            for status in statuses_to_test:
                conn.execute("UPDATE users SET status = ? WHERE email = ?", (status, self.email))
                conn.commit()
                resp = self._request_reset(self.email)
                responses[status] = resp.status_code
        finally:
            conn.execute("UPDATE users SET status = ? WHERE email = ?", (original_status, self.email))
            conn.commit()
            conn.close()
        duration = len(statuses_to_test) * 0.1
        passed = all(code == 200 for code in responses.values())
        errors = []
        if not passed:
            errors.append("Reset flow exposed user status differences.")
        return PasswordResetResult("user_status", passed, duration, {"responses": responses}, errors)

    # ------------------------------------------------------------------
    def run(self) -> List[PasswordResetResult]:
        scenarios = {
            "expiry": self.scenario_token_expiry,
            "single-use": self.scenario_single_use,
            "rate-limit": self.scenario_rate_limit,
            "security": self.scenario_token_security,
            "strength": self.scenario_password_strength,
            "enumeration": self.scenario_enumeration,
            "status": self.scenario_user_status,
        }
        selected = scenarios.values() if self.test_type == "all" else [scenarios[self.test_type]]
        results: List[PasswordResetResult] = []
        for scenario in selected:
            try:
                res = scenario()
                results.append(res)
                status = "PASS" if res.passed else "FAIL"
                print(f"[{status}] {res.name}")
            except Exception as exc:
                results.append(
                    PasswordResetResult(
                        name=scenario.__name__,
                        passed=False,
                        duration=0.0,
                        errors=[str(exc)],
                    )
                )
                print(f"[FAIL] {scenario.__name__}: {exc}")
        return results


def write_report(results: List[PasswordResetResult], output: Optional[Path]) -> Dict[str, Any]:
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
                "details": r.details,
                "errors": r.errors,
            }
            for r in results
        ],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Password reset report saved to {output}")
    else:
        print(json.dumps(summary, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Password reset flow tests")
    parser.add_argument("--url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument(
        "--test-type",
        default="all",
        choices=["expiry", "single-use", "rate-limit", "security", "strength", "enumeration", "status", "all"],
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tester = PasswordResetTester(args.url, args.email, args.test_type)
    results = tester.run()
    write_report(results, args.output)


if __name__ == "__main__":
    main()


