#!/usr/bin/env python3
"""
Audit log analysis utility for PROTON V5.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def format_rows(rows: Iterable[sqlite3.Row]) -> str:
    rows = list(rows)
    if not rows:
        return "No records found."
    headers = rows[0].keys()
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(str(row[header])))
    lines = []
    header_line = " | ".join(f"{header:{widths[header]}}" for header in headers)
    lines.append(header_line)
    lines.append("-+-".join("-" * widths[h] for h in headers))
    for row in rows:
        lines.append(" | ".join(f"{str(row[h]):{widths[h]}}" for h in headers))
    return "\n".join(lines)


def export_data(rows: List[Dict[str, Any]], export_type: Optional[str], output: Optional[Path]) -> None:
    if not export_type or not output:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    if export_type == "json":
        output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    elif export_type == "csv":
        with output.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=rows[0].keys() if rows else [])
            writer.writeheader()
            writer.writerows(rows)
    elif export_type == "html":
        html = "<table><tr>" + "".join(f"<th>{h}</th>" for h in rows[0].keys()) + "</tr>"
        for row in rows:
            html += "<tr>" + "".join(f"<td>{row[h]}</td>" for h in row.keys()) + "</tr>"
        html += "</table>"
        output.write_text(html, encoding="utf-8")
    print(f"Exported {len(rows)} rows to {output}")


def query_mode(conn: sqlite3.Connection, args: argparse.Namespace) -> List[Dict[str, Any]]:
    clauses = []
    params: List[Any] = []
    if args.action:
        clauses.append("action = ?")
        params.append(args.action)
    if args.org_id:
        clauses.append("org_id = ?")
        params.append(args.org_id)
    if args.user_id:
        clauses.append("user_id = ?")
        params.append(args.user_id)
    if args.date_from:
        clauses.append("created_at >= ?")
        params.append(args.date_from)
    if args.date_to:
        clauses.append("created_at <= ?")
        params.append(args.date_to)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    query = f"SELECT id, org_id, user_id, action, details, created_at FROM audit_logs{where} ORDER BY id DESC LIMIT {args.limit}"
    rows = conn.execute(query, params).fetchall()
    print(format_rows(rows))
    return [dict(row) for row in rows]


def analyze_mode(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT action, details, created_at
        FROM audit_logs
        WHERE created_at >= datetime('now', '-7 day')
        """
    ).fetchall()
    findings: List[Dict[str, Any]] = []
    counters = defaultdict(int)
    for row in rows:
        counters[row["action"]] += 1
    if counters["otp_verification_failed"] > 20:
        findings.append({"type": "brute_force", "count": counters["otp_verification_failed"]})
    if counters["password_reset_requested"] > 50:
        findings.append({"type": "password_reset_abuse", "count": counters["password_reset_requested"]})
    print(json.dumps({"findings": findings, "counts": counters}, indent=2, default=str))
    return findings


def stats_mode(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT action, COUNT(1) as count FROM audit_logs GROUP BY action ORDER BY count DESC"
    ).fetchall()
    print(format_rows(rows))
    return [dict(row) for row in rows]


def compliance_mode(conn: sqlite3.Connection, args: argparse.Namespace) -> List[Dict[str, Any]]:
    if not args.org_id and not args.user_id:
        raise ValueError("Compliance reports require --org-id or --user-id.")
    clauses = []
    params: List[Any] = []
    if args.org_id:
        clauses.append("org_id = ?")
        params.append(args.org_id)
    if args.user_id:
        clauses.append("user_id = ?")
        params.append(args.user_id)
    where = " AND ".join(clauses)
    query = f"SELECT * FROM audit_logs WHERE {where} ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    data = [dict(row) for row in rows]
    print(f"Compliance events: {len(data)} rows.")
    return data


def watch_mode(conn: sqlite3.Connection, args: argparse.Namespace) -> None:
    last_id = 0
    try:
        while True:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE id > ? ORDER BY id ASC", (last_id,)
            ).fetchall()
            if rows:
                for row in rows:
                    if args.action and row["action"] != args.action:
                        continue
                    print(f"{row['created_at']} [{row['action']}] org={row['org_id']} user={row['user_id']} {row['details']}")
                last_id = rows[-1]["id"]
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping watch mode.")


def integrity_mode(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = conn.execute("SELECT id, created_at, action, details FROM audit_logs ORDER BY id ASC").fetchall()
    previous_time = None
    anomalies: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        timestamp = datetime.fromisoformat(row["created_at"])
        if previous_time and (timestamp - previous_time).total_seconds() > 3600:
            anomalies.append({"type": "gap", "id": row["id"], "timestamp": row["created_at"]})
        previous_time = timestamp
        fingerprint = (row["created_at"], row["action"], row["details"])
        if fingerprint in seen:
            anomalies.append({"type": "duplicate", "id": row["id"]})
        else:
            seen.add(fingerprint)
        try:
            json.loads(row["details"])
        except json.JSONDecodeError:
            anomalies.append({"type": "invalid_json", "id": row["id"]})
    print(json.dumps({"anomalies": anomalies}, indent=2))
    return anomalies


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit log analysis tool")
    parser.add_argument("--db-path", type=Path, default=Path("primary.db"))
    parser.add_argument(
        "--mode",
        default="query",
        choices=["query", "analyze", "stats", "compliance", "watch", "integrity"],
    )
    parser.add_argument("--action")
    parser.add_argument("--org-id", type=int)
    parser.add_argument("--user-id", type=int)
    parser.add_argument("--date-from")
    parser.add_argument("--date-to")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--export", choices=["json", "csv", "html"])
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    conn = connect(args.db_path)
    try:
        if args.mode == "query":
            rows = query_mode(conn, args)
        elif args.mode == "analyze":
            rows = analyze_mode(conn)
        elif args.mode == "stats":
            rows = stats_mode(conn)
        elif args.mode == "compliance":
            rows = compliance_mode(conn, args)
        elif args.mode == "watch":
            watch_mode(conn, args)
            rows = []
        elif args.mode == "integrity":
            rows = integrity_mode(conn)
        else:
            raise ValueError(f"Unsupported mode: {args.mode}")
        if rows:
            export_data(rows, args.export, args.output)
    finally:
        conn.close()


if __name__ == "__main__":
    main()



