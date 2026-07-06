"""
main.py
SOAR-lite playbook engine.

Loads an alert (JSON) and a playbook (YAML), then runs through the
playbook's steps in order: enrich -> decide severity -> contain
(if warranted) -> open a ticket -> notify the SOC.

Usage:
    python main.py --alert sample_alerts/sample_alert_malicious_ip.json
    python main.py --alert sample_alerts/sample_alert_malicious_ip.json --live-contain
"""

import argparse
import json
import yaml
import datetime
import os

from modules.enrichment import enrich_ip
from modules.containment import contain_host
from modules.ticketing import open_ticket
from modules.notify import send_notification

RUN_LOG_DIR = os.path.join(os.path.dirname(__file__), "evidence")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def decide_severity(score: int, thresholds: dict) -> str:
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def run_playbook(alert: dict, playbook: dict, contain_mode: str = "dry_run") -> dict:
    run_log = {
        "alert_id": alert.get("alert_id"),
        "playbook": playbook["name"],
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "steps": {},
    }

    # 1. Trigger check
    trig = playbook["trigger"]
    if alert.get(trig["alert_field"]) != trig["alert_value"]:
        run_log["result"] = "skipped (trigger condition not met)"
        return run_log

    indicator = alert["indicator_value"]

    # 2. Enrich
    enrichment = enrich_ip(indicator)
    run_log["steps"]["enrich"] = enrichment

    # 3. Decide severity
    thresholds = next(s for s in playbook["steps"] if s["id"] == "decide")["thresholds"]
    severity = decide_severity(enrichment["abuseConfidenceScore"], thresholds)
    run_log["steps"]["decide"] = {"severity": severity}

    # 4. Contain (only if critical)
    if severity == "critical":
        containment = contain_host(indicator, mode=contain_mode)
        run_log["steps"]["contain"] = containment
    else:
        run_log["steps"]["contain"] = {"skipped": True, "reason": f"severity={severity}"}

    # 5. Ticket (always)
    summary = (
        f"Alert {alert.get('alert_id')} on host {alert.get('affected_host')}: "
        f"indicator {indicator} scored {enrichment['abuseConfidenceScore']} "
        f"(severity={severity})"
    )
    ticket = open_ticket(alert.get("alert_id"), indicator, severity, summary)
    run_log["steps"]["ticket"] = ticket

    # 6. Notify (critical or medium)
    if severity in ("critical", "medium"):
        msg = (
            f"[SOC ALERT] {severity.upper()} - {alert.get('alert_id')} "
            f"| IP {indicator} | score={enrichment['abuseConfidenceScore']} "
            f"| ticket #{ticket['ticket_id']}"
        )
        notify_result = send_notification(msg)
        run_log["steps"]["notify"] = notify_result
    else:
        run_log["steps"]["notify"] = {"skipped": True, "reason": f"severity={severity}"}

    run_log["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    run_log["result"] = "completed"
    return run_log


def save_run_log(run_log: dict):
    os.makedirs(RUN_LOG_DIR, exist_ok=True)
    fname = f"run_{run_log['alert_id']}_{run_log['started_at'].replace(':', '-')}.json"
    path = os.path.join(RUN_LOG_DIR, fname)
    with open(path, "w") as f:
        json.dump(run_log, f, indent=2)
    return path


def main():
    parser = argparse.ArgumentParser(description="SOAR-lite playbook engine")
    parser.add_argument("--alert", required=True, help="Path to alert JSON file")
    parser.add_argument("--playbook", default="playbook.yaml", help="Path to playbook YAML")
    parser.add_argument(
        "--live-contain",
        action="store_true",
        help="Actually execute containment command instead of dry-run (use with caution)",
    )
    args = parser.parse_args()

    alert = load_json(args.alert)
    playbook = load_yaml(args.playbook)
    mode = "live" if args.live_contain else "dry_run"

    run_log = run_playbook(alert, playbook, contain_mode=mode)
    log_path = save_run_log(run_log)

    print(json.dumps(run_log, indent=2))
    print(f"\nRun log saved to: {log_path}")


if __name__ == "__main__":
    main()
