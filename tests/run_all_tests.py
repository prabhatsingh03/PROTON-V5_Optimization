#!/usr/bin/env python3
"""
Master runner for the PROTON V5 testing suite.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"
RESULTS_DIR = TESTS_DIR / "results"
TESTING_REPORT = ROOT / "TESTING_REPORT.md"


@dataclass
class TestJob:
    name: str
    command: List[str]
    output: Path


def timestamp() -> str:
    return time.strftime("%Y-%m-%d_%H-%M-%S")


def run_job(job: TestJob) -> Dict[str, any]:
    print(f"\n[RUN] {job.name}")
    start = time.time()
    proc = subprocess.run(job.command, capture_output=True, text=True)
    duration = time.time() - start
    result = {
        "name": job.name,
        "command": " ".join(job.command),
        "returncode": proc.returncode,
        "duration": duration,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "output_file": str(job.output),
    }
    if proc.returncode != 0:
        print(f"[FAIL] {job.name} (rc={proc.returncode})")
        print(proc.stderr)
    else:
        print(f"[PASS] {job.name} ({duration:.1f}s)")
    return result


def load_job_summary(job: TestJob) -> Optional[Dict[str, any]]:
    if job.output.exists():
        try:
            return json.loads(job.output.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


def summarize(all_jobs: List[TestJob], job_results: List[Dict[str, any]]) -> Dict[str, any]:
    summary = {
        "timestamp": timestamp(),
        "jobs": [],
        "totals": {"tests": 0, "passed": 0, "failed": 0},
    }
    for job, result in zip(all_jobs, job_results):
        job_summary = load_job_summary(job)
        passed = job_summary is not None and job_summary.get("failed", 0) == 0
        summary["jobs"].append(
            {
                "name": job.name,
                "status": "passed" if passed else "failed",
                "duration": result["duration"],
                "returncode": result["returncode"],
                "output_file": result["output_file"],
            }
        )
        if job_summary and "total" in job_summary:
            summary["totals"]["tests"] += job_summary["total"]
            summary["totals"]["passed"] += job_summary.get("passed", 0)
            summary["totals"]["failed"] += job_summary.get("failed", 0)
    return summary


def append_report(summary: Dict[str, any]) -> None:
    section = [
        "## Latest Automated Summary",
        f"- Timestamp: {summary['timestamp']}",
        f"- Suites executed: {len(summary['jobs'])}",
        f"- Tests: {summary['totals']['tests']} | Passed: {summary['totals']['passed']} | Failed: {summary['totals']['failed']}",
        "",
    ]
    for job in summary["jobs"]:
        section.append(f"- {job['name']}: {job['status']} ({job['duration']:.1f}s) → {job['output_file']}")
    section_text = "\n".join(section)
    TESTING_REPORT.write_text(
        TESTING_REPORT.read_text(encoding="utf-8") + "\n\n" + section_text,
        encoding="utf-8",
    )


def build_jobs(args: argparse.Namespace) -> List[TestJob]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    base_cmd = [sys.executable]
    timestamp_label = timestamp()
    jobs: List[TestJob] = []

    def add_job(name: str, script: str, extra: List[str]) -> None:
        output_file = RESULTS_DIR / f"{name}_{timestamp_label}.json"
        cmd = base_cmd + [str(TESTS_DIR / script)] + extra + ["--output", str(output_file)]
        jobs.append(TestJob(name=name, command=cmd, output=output_file))

    url = ["--url", args.url]
    email = ["--email", args.email]
    password = ["--password", args.password] if args.password else []

    add_job("email_delivery", "test_email_delivery.py", url + email + password + ["--test-type", "all"])
    add_job("otp_security", "test_otp_security.py", url + email + password + ["--test-type", "all"])
    add_job("password_reset", "test_password_reset.py", url + email + ["--test-type", "all"])
    add_job("payment_idempotency", "test_payment_idempotency.py", url + email + password + ["--threads", str(args.threads)])
    end_to_end_extra = url + ["--scenario", "all"]
    if args.cleanup:
        end_to_end_extra.append("--cleanup")
    add_job("end_to_end", "test_end_to_end.py", end_to_end_extra)
    add_job("audit_logs", "test_audit_logs.py", ["--mode", "stats"])
    add_job(
        "auth_load",
        "test_load_auth.py",
        url + email + password + ["--scenario", "all", "--users", str(args.users)],
    )
    return jobs


def load_config(config_path: Optional[Path]) -> Dict[str, any]:
    if not config_path:
        return {}
    return json.loads(config_path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run all PROTON V5 test suites")
    parser.add_argument("--url", default="http://127.0.0.1:5125")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--otp")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--skip-tests", help="Comma-separated list of suites to skip")
    parser.add_argument("--only-tests", help="Comma-separated list of suites to run")
    parser.add_argument("--backup-db", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=RESULTS_DIR)
    return parser.parse_args()


def maybe_backup_db(enable: bool) -> None:
    if not enable:
        return
    src = ROOT / "primary.db"
    if src.exists():
        target = ROOT / f"primary_backup_{timestamp()}.db"
        shutil.copy(src, target)
        print(f"Database backup created at {target}")


def main() -> None:
    args = parse_args()
    config_data = load_config(args.config)
    for key, value in config_data.items():
        setattr(args, key, value)
    maybe_backup_db(args.backup_db)

    jobs = build_jobs(args)
    if args.skip_tests:
        skips = {name.strip() for name in args.skip_tests.split(",")}
        jobs = [job for job in jobs if job.name not in skips]
    if args.only_tests:
        allowed = {name.strip() for name in args.only_tests.split(",")}
        jobs = [job for job in jobs if job.name in allowed]

    job_results: List[Dict[str, any]] = []
    for job in jobs:
        result = run_job(job)
        job_results.append(result)

    summary = summarize(jobs, job_results)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = RESULTS_DIR / f"summary_{summary['timestamp']}.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nOverall Summary saved to {summary_path}")

    append_report(summary)
    print("TESTING_REPORT.md updated with latest summary.")


if __name__ == "__main__":
    main()


