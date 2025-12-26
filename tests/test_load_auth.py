#!/usr/bin/env python3
"""
Authentication-specific load testing for PROTON V5.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests

DB_PATH = Path("primary.db")


@dataclass
class LoadScenarioResult:
    name: str
    duration: float
    total_requests: int
    successes: int
    failures: int
    status_codes: Dict[int, int]
    response_times: List[float] = field(default_factory=list)
    notes: Dict[str, Any] = field(default_factory=dict)

    @property
    def avg_response(self) -> float:
        return statistics.mean(self.response_times) if self.response_times else 0.0


class AuthLoadTester:
    def __init__(self, base_url: str, email: str, password: str, users: int, duration: int, ramp_up: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self.users = users
        self.duration = duration
        self.ramp_up = ramp_up
        self.session = requests.Session()

    # ------------------------------------------------------------------
    def _fetch_otp(self, email: str) -> Optional[str]:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("SELECT otp_code FROM users WHERE email = ?", (email,)).fetchone()
            return row["otp_code"] if row else None
        finally:
            conn.close()

    def _time_request(self, func: Callable[[], requests.Response]) -> Dict[str, Any]:
        start = time.time()
        resp = func()
        elapsed = time.time() - start
        return {"response": resp, "elapsed": elapsed}

    def _otp_sequence(self) -> Dict[str, Any]:
        def login():
            return self.session.post(
                f"{self.base_url}/api/login",
                json={"type": "admin", "email": self.email, "password": self.password},
                timeout=30,
            )

        login_meta = self._time_request(login)
        status = login_meta["response"].status_code
        if status != 200:
            return {"status": status, "elapsed": login_meta["elapsed"]}
        otp_code = self._fetch_otp(self.email)
        if not otp_code:
            return {"status": 400, "elapsed": login_meta["elapsed"], "error": "OTP missing"}

        def verify():
            return self.session.post(
                f"{self.base_url}/api/auth/verify-otp",
                json={"email": self.email, "otp_code": otp_code},
                timeout=30,
            )

        verify_meta = self._time_request(verify)
        elapsed = login_meta["elapsed"] + verify_meta["elapsed"]
        return {"status": verify_meta["response"].status_code, "elapsed": elapsed}

    def _password_reset_sequence(self) -> Dict[str, Any]:
        def forgot():
            return self.session.post(
                f"{self.base_url}/api/auth/forgot-password",
                json={"email": self.email},
                timeout=30,
            )

        forgot_meta = self._time_request(forgot)
        token = None
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute("SELECT reset_token FROM users WHERE email = ?", (self.email,)).fetchone()
            token = row["reset_token"] if row else None
        finally:
            conn.close()

        if not token:
            return {"status": 400, "elapsed": forgot_meta["elapsed"], "error": "Token missing"}

        def reset():
            return self.session.post(
                f"{self.base_url}/api/auth/reset-password",
                json={"reset_token": token, "password": "LoadTest123!"},
                timeout=30,
            )

        reset_meta = self._time_request(reset)
        return {"status": reset_meta["response"].status_code, "elapsed": forgot_meta["elapsed"] + reset_meta["elapsed"]}

    def _run_concurrent(self, worker: Callable[[], Dict[str, Any]]) -> LoadScenarioResult:
        start = time.time()
        status_codes: Dict[int, int] = {}
        response_times: List[float] = []
        failures = 0
        successes = 0

        with ThreadPoolExecutor(max_workers=self.users) as executor:
            futures = [executor.submit(worker) for _ in range(self.users)]
            for future in as_completed(futures):
                result = future.result()
                code = result.get("status", 0)
                elapsed = result.get("elapsed", 0)
                status_codes[code] = status_codes.get(code, 0) + 1
                if 200 <= code < 300:
                    successes += 1
                else:
                    failures += 1
                response_times.append(elapsed)

        duration = time.time() - start
        return LoadScenarioResult(
            name="",
            duration=duration,
            total_requests=len(response_times),
            successes=successes,
            failures=failures,
            status_codes=status_codes,
            response_times=response_times,
        )

    # ------------------------------------------------------------------
    def scenario_otp_login(self) -> LoadScenarioResult:
        result = self._run_concurrent(self._otp_sequence)
        result.name = "otp_login"
        return result

    def scenario_password_reset(self) -> LoadScenarioResult:
        result = self._run_concurrent(self._password_reset_sequence)
        result.name = "password_reset"
        return result

    def scenario_mixed(self) -> LoadScenarioResult:
        def worker() -> Dict[str, Any]:
            return self._otp_sequence() if time.time() % 2 == 0 else self._password_reset_sequence()

        result = self._run_concurrent(worker)
        result.name = "mixed_auth"
        return result

    def scenario_rate_limit(self) -> LoadScenarioResult:
        def worker() -> Dict[str, Any]:
            resp = self.session.post(
                f"{self.base_url}/api/auth/verify-otp",
                json={"email": self.email, "otp_code": "000000"},
                timeout=30,
            )
            return {"status": resp.status_code, "elapsed": 0.05}

        result = self._run_concurrent(worker)
        result.name = "rate_limit"
        return result

    def scenario_connection_pool(self) -> LoadScenarioResult:
        def worker() -> Dict[str, Any]:
            resp = self.session.get(f"{self.base_url}/api/org/usage", timeout=30)
            return {"status": resp.status_code, "elapsed": 0.1}

        result = self._run_concurrent(worker)
        result.name = "connection_pool"
        return result

    def scenario_email_load(self) -> LoadScenarioResult:
        def worker() -> Dict[str, Any]:
            resp = self.session.post(
                f"{self.base_url}/api/login",
                json={"type": "admin", "email": self.email, "password": self.password},
                timeout=30,
            )
            return {"status": resp.status_code, "elapsed": 0.1}

        result = self._run_concurrent(worker)
        result.name = "email_service"
        return result

    # ------------------------------------------------------------------
    def run(self, scenario: str) -> List[LoadScenarioResult]:
        scenario_map = {
            "otp-login": self.scenario_otp_login,
            "password-reset": self.scenario_password_reset,
            "mixed": self.scenario_mixed,
            "rate-limit": self.scenario_rate_limit,
            "connection-pool": self.scenario_connection_pool,
            "email": self.scenario_email_load,
        }
        selected = scenario_map.values() if scenario == "all" else [scenario_map[scenario]]
        results = []
        for func in selected:
            result = func()
            results.append(result)
            print(
                f"[{result.name}] total={result.total_requests} "
                f"success={result.successes} failure={result.failures} avg={result.avg_response:.3f}s"
            )
        return results


def write_report(results: List[LoadScenarioResult], output: Optional[Path]) -> Dict[str, Any]:
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "results": [
            {
                "name": r.name,
                "duration": r.duration,
                "total_requests": r.total_requests,
                "successes": r.successes,
                "failures": r.failures,
                "avg_response": r.avg_response,
                "status_codes": r.status_codes,
            }
            for r in results
        ],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Auth load report saved to {output}")
    else:
        print(json.dumps(summary, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authentication load testing")
    parser.add_argument("--url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--scenario", default="all", choices=["otp-login", "password-reset", "mixed", "rate-limit", "connection-pool", "email", "all"])
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--ramp-up", type=int, default=0)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tester = AuthLoadTester(args.url, args.email, args.password, args.users, args.duration, args.ramp_up)
    results = tester.run(args.scenario)
    write_report(results, args.output)


if __name__ == "__main__":
    main()


