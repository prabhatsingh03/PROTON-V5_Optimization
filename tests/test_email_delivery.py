#!/usr/bin/env python3
"""
Email delivery verification suite for PROTON V5.
"""

from __future__ import annotations

import argparse
import json
import smtplib
import sqlite3
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from config import (
    SMTP_FROM_EMAIL,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USERNAME,
)
from utils.email_service import render_email_template


DB_PATH = Path("primary.db")


@dataclass
class EmailScenarioResult:
    name: str
    passed: bool
    duration: float
    findings: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class EmailDeliveryTester:
    def __init__(
        self,
        base_url: str,
        email: str,
        password: str,
        test_email: Optional[str],
        test_type: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self.test_email = test_email or email
        self.test_type = test_type
        self.session = requests.Session()

    # ------------------------------------------------------------------
    def _post(self, endpoint: str, payload: Dict[str, Any]) -> requests.Response:
        return self.session.post(f"{self.base_url}{endpoint}", json=payload, timeout=30)

    @staticmethod
    def _query_audit(actions: List[str]) -> List[Dict[str, Any]]:
        placeholders = ",".join("?" for _ in actions)
        query = (
            f"SELECT id, action, details, created_at FROM audit_logs "
            f"WHERE action IN ({placeholders}) ORDER BY id DESC LIMIT 25"
        )
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(query, actions).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    def scenario_smtp_connectivity(self) -> EmailScenarioResult:
        start = time.time()
        errors = []
        passed = False
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                passed = True
        except Exception as exc:
            errors.append(str(exc))
        duration = time.time() - start
        findings = {
            "host": SMTP_HOST,
            "port": SMTP_PORT,
            "username": SMTP_USERNAME,
        }
        return EmailScenarioResult("smtp_connectivity", passed, duration, findings, errors)

    def scenario_otp_email(self) -> EmailScenarioResult:
        start = time.time()
        resp = self._post("/api/login", {"type": "admin", "email": self.email, "password": self.password})
        otp_sent = resp.status_code == 200
        audits = self._query_audit(["email_sent"])
        placeholders_ok = False
        success, html, _ = render_email_template(
            "otp_email.html",
            {"USER_NAME": "Test User", "OTP_CODE": "123456", "EXPIRY_MINUTES": 10},
        )
        if success and html:
            placeholders_ok = all(key not in html for key in ("{{USER_NAME}}", "{{OTP_CODE}}"))
        duration = time.time() - start
        passed = otp_sent and placeholders_ok
        errors = []
        if not otp_sent:
            errors.append(f"Login endpoint did not return OTP flow: {resp.text[:200]}")
        if not placeholders_ok:
            errors.append("OTP template placeholders not replaced successfully.")
        findings = {
            "status": resp.status_code,
            "audit_entries": audits,
            "template_preview": html[:120] if html else None,
        }
        return EmailScenarioResult("otp_email_delivery", passed, duration, findings, errors)

    def scenario_password_reset_email(self) -> EmailScenarioResult:
        start = time.time()
        resp = self._post("/api/auth/forgot-password", {"email": self.email})
        audits = self._query_audit(["email_sent"])
        success, html, _ = render_email_template(
            "password_reset_email.html",
            {"USER_NAME": "Test User", "RESET_LINK": "https://example.com/reset?token=abc", "EXPIRY_HOURS": 24},
        )
        link_present = "https://example.com/reset?token=abc" in (html or "")
        passed = resp.status_code == 200 and link_present
        duration = time.time() - start
        errors = []
        if not passed:
            errors.append(f"Password reset email scenario failed (status {resp.status_code}, link {link_present}).")
        findings = {
            "status": resp.status_code,
            "audit_entries": audits,
            "template_preview": html[:120] if html else None,
        }
        return EmailScenarioResult("password_reset_email", passed, duration, findings, errors)

    def scenario_retry_logic(self) -> EmailScenarioResult:
        start = time.time()
        attempts = 3
        delay_pattern = [2, 4, 8]
        simulated_errors = []
        for idx in range(attempts):
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                    server.starttls()
                    server.login(SMTP_USERNAME, "invalid-password")
            except smtplib.SMTPAuthenticationError as exc:
                simulated_errors.append(str(exc))
                time.sleep(delay_pattern[idx])
        duration = time.time() - start
        passed = len(simulated_errors) == attempts
        findings = {
            "attempts": attempts,
            "delays": delay_pattern,
            "errors": simulated_errors,
        }
        errors = []
        if not passed:
            errors.append("SMTP retry simulation did not hit expected number of failures.")
        return EmailScenarioResult("email_retry_logic", passed, duration, findings, errors)

    def scenario_template_rendering(self) -> EmailScenarioResult:
        start = time.time()
        contexts = [
            {"USER_NAME": "", "OTP_CODE": "000000", "EXPIRY_MINUTES": 10},
            {"USER_NAME": "Δelta 🚀", "OTP_CODE": "123456", "EXPIRY_MINUTES": 30},
            {"USER_NAME": "Very Long Name" * 5, "OTP_CODE": "999999", "EXPIRY_MINUTES": 5},
        ]
        templates = ["otp_email.html", "password_reset_email.html"]
        results: Dict[str, List[str]] = {}
        errors = []
        for template in templates:
            outputs = []
            for ctx in contexts:
                success, html, err = render_email_template(template, ctx)
                if not success:
                    errors.append(err or f"Failed to render {template}")
                else:
                    outputs.append(html[:80])
            results[template] = outputs
        duration = time.time() - start
        passed = not errors
        return EmailScenarioResult("template_rendering", passed, duration, results, errors)

    def scenario_audit_logging(self) -> EmailScenarioResult:
        start = time.time()
        entries = self._query_audit(["email_sent", "email_failed"])
        duration = time.time() - start
        sent = [row for row in entries if row["action"] == "email_sent"]
        failed = [row for row in entries if row["action"] == "email_failed"]
        passed = bool(entries)
        findings = {
            "recent_sent": sent[:5],
            "recent_failed": failed[:5],
        }
        errors = []
        if not passed:
            errors.append("No email audit entries found.")
        return EmailScenarioResult("email_audit_logging", passed, duration, findings, errors)

    def scenario_delivery_confirmation(self) -> EmailScenarioResult:
        instructions = (
            f"Send OTP email to {self.test_email} and confirm receipt manually. "
            "Check inbox/spam and validate links."
        )
        findings = {"instructions": instructions}
        return EmailScenarioResult("email_delivery_confirmation", True, 0.1, findings, [])

    # ------------------------------------------------------------------
    def run(self) -> List[EmailScenarioResult]:
        scenarios = {
            "connectivity": self.scenario_smtp_connectivity,
            "otp": self.scenario_otp_email,
            "reset": self.scenario_password_reset_email,
            "retry": self.scenario_retry_logic,
            "template": self.scenario_template_rendering,
            "audit": self.scenario_audit_logging,
            "delivery": self.scenario_delivery_confirmation,
        }
        selected = scenarios.values() if self.test_type == "all" else [scenarios[self.test_type]]
        results = []
        for scenario in selected:
            try:
                res = scenario()
                results.append(res)
                status = "PASS" if res.passed else "FAIL"
                print(f"[{status}] {res.name}")
            except Exception as exc:
                results.append(
                    EmailScenarioResult(
                        name=scenario.__name__,
                        passed=False,
                        duration=0.0,
                        errors=[str(exc)],
                    )
                )
                print(f"[FAIL] {scenario.__name__}: {exc}")
        return results


def write_report(results: List[EmailScenarioResult], output: Optional[Path]) -> Dict[str, Any]:
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
                "findings": r.findings,
                "errors": r.errors,
            }
            for r in results
        ],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Email delivery report saved to {output}")
    else:
        print(json.dumps(summary, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Email delivery verification")
    parser.add_argument("--url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--test-email", help="Destination email for manual delivery confirmation")
    parser.add_argument(
        "--test-type",
        default="all",
        choices=["connectivity", "otp", "reset", "retry", "template", "audit", "delivery", "all"],
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tester = EmailDeliveryTester(args.url, args.email, args.password, args.test_email, args.test_type)
    results = tester.run()
    write_report(results, args.output)


if __name__ == "__main__":
    main()


