#!/usr/bin/env python3
"""
End-to-end scenario tests for PROTON V5.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


DB_PATH = Path("primary.db")


@dataclass
class JourneyResult:
    name: str
    passed: bool
    duration: float
    steps: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class EndToEndTester:
    def __init__(self, base_url: str, cleanup: bool) -> None:
        self.base_url = base_url.rstrip("/")
        self.cleanup = cleanup
        self.session = requests.Session()
        self.created_emails: List[str] = []
        self.created_org_ids: List[int] = []

    # ------------------------------------------------------------------
    def _post(self, path: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> requests.Response:
        return self.session.post(f"{self.base_url}{path}", json=payload, headers=headers, timeout=60)

    def _get(self, path: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
        return self.session.get(f"{self.base_url}{path}", headers=headers, timeout=60)

    @staticmethod
    def _fetch_user(email: str) -> Optional[sqlite3.Row]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute("SELECT id, email, otp_code FROM users WHERE email = ?", (email,))
            return cur.fetchone()
        finally:
            conn.close()

    def _otp_login(self, email: str, password: str) -> Optional[str]:
        login_resp = self._post("/api/login", {"type": "admin", "email": email, "password": password})
        if login_resp.status_code != 200:
            raise RuntimeError(f"Login failed: {login_resp.text[:200]}")
        status = login_resp.json().get("status")
        if status == "success":
            return login_resp.json().get("access_token")
        if status != "otp_sent":
            raise RuntimeError(f"Unexpected login flow: {login_resp.text[:200]}")
        user_row = self._fetch_user(email)
        if not user_row or not user_row["otp_code"]:
            raise RuntimeError("OTP not available in database.")
        verify_resp = self._post("/api/auth/verify-otp", {"email": email, "otp_code": user_row["otp_code"]})
        if verify_resp.status_code != 200:
            raise RuntimeError(f"OTP verification failed: {verify_resp.text[:200]}")
        return verify_resp.json().get("access_token")

    # ------------------------------------------------------------------
    def scenario_signup_upgrade(self) -> JourneyResult:
        start = time.time()
        errors: List[str] = []
        steps: List[Dict[str, Any]] = []
        email = f"orgadmin+{uuid.uuid4().hex[:8]}@example.com"
        password = "TestPass123!"
        org_payload = {
            "org_name": f"Test Org {uuid.uuid4().hex[:4]}",
            "full_name": "Test Admin",
            "email": email,
            "password": password,
            "industry": "Digital",
        }
        resp = self._post("/api/signup", org_payload)
        steps.append({"action": "signup", "status": resp.status_code})
        if resp.status_code != 201:
            errors.append(f"Signup failed: {resp.text[:200]}")
        else:
            self.created_emails.append(email)
        token = None
        try:
            token = self._otp_login(email, password)
        except Exception as exc:
            errors.append(str(exc))
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            dashboard = self._get("/api/org/trial-status", headers=headers)
            steps.append({"action": "trial_status", "status": dashboard.status_code})
            upgrade_payload = {
                "plan_type": "basic",
                "billing_cycle": "monthly",
                "request_id": str(uuid.uuid4()),
            }
            upgrade_resp = self._post("/api/org/subscription/upgrade", upgrade_payload, headers=headers)
            steps.append({"action": "upgrade_request", "status": upgrade_resp.status_code})
            verify_resp = self._post(
                "/api/razorpay/subscription/verify",
                {
                    "razorpay_payment_id": f"pay_{uuid.uuid4().hex}",
                    "razorpay_subscription_id": f"sub_{uuid.uuid4().hex}",
                    "razorpay_signature": uuid.uuid4().hex,
                },
                headers=headers,
            )
            steps.append({"action": "payment_verify", "status": verify_resp.status_code})
        passed = not errors and token is not None
        duration = time.time() - start
        return JourneyResult("signup_upgrade", passed, duration, steps, errors)

    def scenario_password_reset(self) -> JourneyResult:
        start = time.time()
        email = self.created_emails[0] if self.created_emails else f"existing+{uuid.uuid4().hex[:8]}@example.com"
        resp = self._post("/api/login", {"type": "admin", "email": email, "password": "WrongPass!"})
        steps = [{"action": "invalid_login", "status": resp.status_code}]
        forgot = self._post("/api/auth/forgot-password", {"email": email})
        steps.append({"action": "forgot_password", "status": forgot.status_code})
        row = self._fetch_user(email)
        token = row["reset_token"] if row else None
        reset_resp = self._post("/api/auth/reset-password", {"reset_token": token or "", "password": "BrandNew123!"})
        steps.append({"action": "reset_password", "status": reset_resp.status_code})
        passed = reset_resp.status_code in (200, 204)
        errors = []
        if not token:
            errors.append("Reset token not found in database.")
        if not passed:
            errors.append(f"Password reset failed: {reset_resp.text[:200]}")
        duration = time.time() - start
        return JourneyResult("password_reset", passed, duration, steps, errors)

    def scenario_otp_login(self) -> JourneyResult:
        start = time.time()
        email = self.created_emails[0] if self.created_emails else f"otp+{uuid.uuid4().hex[:8]}@example.com"
        password = "TestPass123!"
        steps = []
        try:
            token = self._otp_login(email, password)
            steps.append({"action": "otp_login", "status": 200})
            headers = {"Authorization": f"Bearer {token}"}
            usage = self._get("/api/org/usage", headers=headers)
            steps.append({"action": "usage", "status": usage.status_code})
            passed = usage.status_code == 200
        except Exception as exc:
            steps.append({"action": "otp_login", "status": 400})
            passed = False
            errors = [str(exc)]
        else:
            errors = []
        duration = time.time() - start
        return JourneyResult("otp_login", passed, duration, steps, errors)

    def scenario_superadmin(self) -> JourneyResult:
        start = time.time()
        email = "superadmin@proton.com"
        password = "SuperSecret123!"
        steps = []
        errors = []
        try:
            token = self._otp_login(email, password)
            headers = {"Authorization": f"Bearer {token}"}
            orgs = self._get("/api/superadmin/organizations", headers=headers)
            steps.append({"action": "superadmin_orgs", "status": orgs.status_code})
            passed = orgs.status_code == 200
        except Exception as exc:
            errors.append(str(exc))
            passed = False
        duration = time.time() - start
        return JourneyResult("superadmin_journey", passed, duration, steps, errors)

    def scenario_collaboration(self) -> JourneyResult:
        start = time.time()
        email = self.created_emails[0] if self.created_emails else f"collab+{uuid.uuid4().hex[:8]}@example.com"
        password = "TestPass123!"
        steps = []
        errors = []
        try:
            token = self._otp_login(email, password)
            headers = {"Authorization": f"Bearer {token}"}
            project_resp = self._post("/api/projects", {"name": "Automation Project"}, headers=headers)
            steps.append({"action": "create_project", "status": project_resp.status_code})
            invite_payload = {"email": f"user+{uuid.uuid4().hex[:4]}@example.com", "role": "org_user"}
            invite_resp = self._post("/api/org/users", invite_payload, headers=headers)
            steps.append({"action": "invite_user", "status": invite_resp.status_code})
            passed = project_resp.status_code == 201 and invite_resp.status_code in (200, 201)
        except Exception as exc:
            errors.append(str(exc))
            passed = False
        duration = time.time() - start
        return JourneyResult("multi_user_collaboration", passed, duration, steps, errors)

    def scenario_idempotency(self) -> JourneyResult:
        start = time.time()
        email = self.created_emails[0] if self.created_emails else f"idempotent+{uuid.uuid4().hex[:8]}@example.com"
        password = "TestPass123!"
        steps = []
        errors = []
        try:
            token = self._otp_login(email, password)
            headers = {"Authorization": f"Bearer {token}"}
            rid = str(uuid.uuid4())
            first = self._post(
                "/api/org/subscription/upgrade",
                {"plan_type": "plus", "billing_cycle": "monthly", "request_id": rid},
                headers=headers,
            )
            second = self._post(
                "/api/org/subscription/upgrade",
                {"plan_type": "plus", "billing_cycle": "monthly", "request_id": rid},
                headers=headers,
            )
            steps.extend(
                [
                    {"action": "upgrade_first", "status": first.status_code},
                    {"action": "upgrade_duplicate", "status": second.status_code},
                ]
            )
            passed = first.status_code in (200, 201) and second.status_code == 200
        except Exception as exc:
            errors.append(str(exc))
            passed = False
        duration = time.time() - start
        return JourneyResult("payment_idempotency_flow", passed, duration, steps, errors)

    def scenario_subscription_lifecycle(self) -> JourneyResult:
        start = time.time()
        email = self.created_emails[0] if self.created_emails else f"lifecycle+{uuid.uuid4().hex[:8]}@example.com"
        password = "TestPass123!"
        steps = []
        errors = []
        plans = ["basic", "plus", "pro"]
        try:
            token = self._otp_login(email, password)
            headers = {"Authorization": f"Bearer {token}"}
            for plan in plans:
                resp = self._post(
                    "/api/org/subscription/upgrade",
                    {"plan_type": plan, "billing_cycle": "monthly", "request_id": str(uuid.uuid4())},
                    headers=headers,
                )
                steps.append({"action": f"upgrade_{plan}", "status": resp.status_code})
            passed = all(step["status"] in (200, 201) for step in steps)
        except Exception as exc:
            errors.append(str(exc))
            passed = False
        duration = time.time() - start
        return JourneyResult("subscription_lifecycle", passed, duration, steps, errors)

    # ------------------------------------------------------------------
    def cleanup_data(self) -> None:
        if not self.cleanup or not self.created_emails:
            return
        conn = sqlite3.connect(DB_PATH)
        try:
            for email in self.created_emails:
                conn.execute("DELETE FROM users WHERE email = ?", (email,))
            conn.commit()
        finally:
            conn.close()

    def run(self, scenario: str) -> List[JourneyResult]:
        scenario_map = {
            "signup-upgrade": self.scenario_signup_upgrade,
            "password-reset": self.scenario_password_reset,
            "otp-login": self.scenario_otp_login,
            "superadmin": self.scenario_superadmin,
            "collaboration": self.scenario_collaboration,
            "idempotency": self.scenario_idempotency,
            "lifecycle": self.scenario_subscription_lifecycle,
        }
        selected = scenario_map.values() if scenario == "all" else [scenario_map[scenario]]
        results: List[JourneyResult] = []
        for func in selected:
            try:
                result = func()
                results.append(result)
                status = "PASS" if result.passed else "FAIL"
                print(f"[{status}] {result.name}")
            except Exception as exc:
                results.append(
                    JourneyResult(
                        name=func.__name__,
                        passed=False,
                        duration=0.0,
                        errors=[str(exc)],
                    )
                )
                print(f"[FAIL] {func.__name__}: {exc}")
        self.cleanup_data()
        return results


def write_report(results: List[JourneyResult], output: Optional[Path]) -> Dict[str, Any]:
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "journeys": [
            {
                "name": r.name,
                "passed": r.passed,
                "duration": r.duration,
                "steps": r.steps,
                "errors": r.errors,
            }
            for r in results
        ],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"End-to-end report saved to {output}")
    else:
        print(json.dumps(summary, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="End-to-end test scenarios")
    parser.add_argument("--url", required=True)
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["signup-upgrade", "password-reset", "otp-login", "superadmin", "collaboration", "idempotency", "lifecycle", "all"],
    )
    parser.add_argument("--cleanup", action="store_true", help="Delete created records after scenarios")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tester = EndToEndTester(args.url, args.cleanup)
    results = tester.run(args.scenario)
    write_report(results, args.output)


if __name__ == "__main__":
    main()



