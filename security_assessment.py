
#!/usr/bin/env python3
"""Read-only defensive security assessment for Kali Linux."""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def command_output(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def system_checks():
    findings = [{
        "check": "Operating system",
        "status": platform.platform(),
        "risk": "INFO",
        "recommendation": "Keep the operating system updated."
    }]

    if hasattr(os, "geteuid"):
        is_root = os.geteuid() == 0
        findings.append({
            "check": "Execution privilege",
            "status": "Running as root" if is_root
                      else "Running as non-root user",
            "risk": "MEDIUM" if is_root else "LOW",
            "recommendation": "Use a normal user for routine checks."
        })

    if shutil.which("ufw"):
        status = command_output(["ufw", "status"])
        if status:
            active = "Status: active" in status
            findings.append({
                "check": "UFW firewall",
                "status": status.splitlines()[0],
                "risk": "LOW" if active else "MEDIUM",
                "recommendation": "Review firewall status and rules."
            })
        else:
            findings.append({
                "check": "UFW firewall",
                "status": "Status could not be read",
                "risk": "INFO",
                "recommendation": "Check firewall status manually."
            })
    else:
        findings.append({
            "check": "UFW firewall utility",
            "status": "UFW is not installed",
            "risk": "INFO",
            "recommendation": (
                "Check the firewall actually used by this system. "
                "Missing UFW does not mean no firewall exists."
            )
        })

    updates = command_output(["apt", "list", "--upgradable"])
    if updates:
        lines = [
            line for line in updates.splitlines()
            if "/" in line and not line.startswith("Listing")
        ]
        findings.append({
            "check": "Available package updates",
            "status": f"{len(lines)} upgradable package entries",
            "risk": "MEDIUM" if lines else "LOW",
            "recommendation": "Review and apply approved updates."
        })
    else:
        findings.append({
            "check": "Available package updates",
            "status": "Could not determine update status",
            "risk": "INFO",
            "recommendation": "Review apt list --upgradable manually."
        })

    return findings


def analyze_log(log_path, threshold):
    counts = Counter()
    total_failed = 0

    try:
        with log_path.open(
            "r", encoding="utf-8", errors="replace"
        ) as handle:
            for line in handle:
                if re.search(
                    r"login failed|failed password|authentication failure",
                    line,
                    re.IGNORECASE
                ):
                    match = re.search(
                        r"(?:user|username)=([A-Za-z0-9_.@-]+)",
                        line,
                        re.IGNORECASE
                    )
                    username = match.group(1) if match else "unknown"
                    counts[username] += 1
                    total_failed += 1
    except OSError as exc:
        return [], {"error": str(exc)}

    findings = [{
        "check": "Failed authentication events",
        "status": f"{total_failed} failed event(s)",
        "risk": "INFO",
        "recommendation": (
            "Review events in context. Failed attempts alone do not "
            "prove malicious activity."
        )
    }]

    for username, count in sorted(counts.items()):
        if count >= threshold:
            findings.append({
                "check": f"Repeated failures for {username}",
                "status": f"{count} failed event(s)",
                "risk": "MEDIUM",
                "recommendation": (
                    "Review timestamps and context before taking action."
                )
            })

    return findings, {
        "total_failed_events": total_failed,
        "counts_by_username": dict(counts)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Read-only defensive security assessment"
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("sample_logs/auth.log"),
        help="Authentication log to analyze"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failures that trigger a review finding"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("assessment_report.json"),
        help="JSON report output path"
    )
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    findings = system_checks()
    log_findings, summary = analyze_log(args.log, args.threshold)
    findings.extend(log_findings)

    report = {
        "title": "Defense Security Assessment",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Local read-only checks and supplied log only",
        "log_summary": summary,
        "findings": findings,
        "limitations": [
            "This educational tool is not a full security audit.",
            "A missing UFW utility does not prove no firewall exists.",
            "Failed logins are investigation leads, not proof of attack.",
            "Review findings manually before making security decisions."
        ]
    }

    print("=== Defense Security Assessment ===")
    print("Platform:", platform.platform())

    if "error" in summary:
        print("Log analysis error:", summary["error"])
    else:
        print("Failed login events:", summary["total_failed_events"])
        for username, count in sorted(
            summary["counts_by_username"].items()
        ):
            print(f"  {username}: {count}")

    print("\nFindings:")
    for finding in findings:
        print(
            f"[{finding['risk']}] {finding['check']} - "
            f"{finding['status']}"
        )
        print("  Recommendation:", finding["recommendation"])

    try:
        args.output.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8"
        )
        print(f"\nJSON report saved to: {args.output}")
    except OSError as exc:
        print("Could not save report:", exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
