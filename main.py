"""
main.py
Dynamic SOAR playbook engine.

Loads an alert (JSON) and a playbook (YAML), then executes the playbook's steps
dynamically based on conditions evaluated securely with AST condition parsing.

Usage:
    py main.py --alert sample_alerts/sample_alert_malicious_ip.json
    py main.py --alert sample_alerts/sample_alert_malicious_ip.json --live-contain
"""

import argparse
import json
import yaml
import datetime
import os
import sys

from modules.enrichment import enrich_ip
from modules.containment import contain_host
from modules.ticketing import open_ticket
from modules.notify import send_notification
from modules.safe_eval import safe_eval_condition

RUN_LOG_DIR = os.path.join(os.path.dirname(__file__), "evidence")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def decide_severity_action(score: int, thresholds: dict) -> dict:
    critical_t = thresholds.get("critical", 75)
    high_t = thresholds.get("high", 50)
    medium_t = thresholds.get("medium", 25)
    low_t = thresholds.get("low", 0)

    if not isinstance(score, (int, float)) or score < 0 or score > 100:
        return {"severity": "unknown_requires_review"}

    if score >= critical_t:
        severity = "critical"
    elif score >= high_t:
        severity = "high"
    elif score >= medium_t:
        severity = "medium"
    elif score >= low_t:
        severity = "low"
    else:
        severity = "unknown_requires_review"
    return {"severity": severity}


# Action registry to map YAML actions to Python functions
ACTION_REGISTRY = {
    "enrich_ip": enrich_ip,
    "decide_severity": decide_severity_action,
    "contain_host": contain_host,
    "open_ticket": open_ticket,
    "send_notification": send_notification,
}


def run_playbook(alert: dict, playbook: dict, contain_mode: str = "dry_run", log_callback=None) -> dict:
    def log_msg(msg):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)

    run_log = {
        "alert_id": alert.get("alert_id"),
        "playbook": playbook["name"],
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "steps": {},
    }

    # 1. Trigger check
    trig = playbook.get("trigger", {})
    alert_field = trig.get("alert_field")
    alert_value = trig.get("alert_value")

    if alert.get(alert_field) != alert_value:
        msg = f"[-] Playbook skipped: trigger condition '{alert_field} == {alert_value}' not met (got '{alert.get(alert_field)}')"
        log_msg(msg)
        run_log["result"] = "skipped (trigger condition not met)"
        return run_log

    log_msg(f"[+] Starting playbook '{playbook['name']}' for alert {alert.get('alert_id')}")

    # Shared execution context for variables and conditions
    context = {
        "alert_id": alert.get("alert_id"),
        "indicator_value": alert.get("indicator_value"),
        "affected_host": alert.get("affected_host"),
        "severity": "low",  # Default severity
        "abuseConfidenceScore": 0,
        "ticket_id": None,
    }

    # 2. Iterate through steps dynamically
    for step in playbook.get("steps", []):
        step_id = step["id"]
        action_name = step["action"]
        always_run = step.get("always_run", False)

        log_msg(f"\n[+] Step '{step_id}': Action = {action_name}")

        # Check condition if present and step is not marked always_run
        if "condition" in step and not always_run:
            condition_str = step["condition"]
            try:
                should_run = safe_eval_condition(condition_str, context)
            except Exception as e:
                log_msg(f"[-] Step '{step_id}' error parsing condition '{condition_str}': {e}")
                run_log["steps"][step_id] = {"error": f"Condition evaluation failed: {e}", "status": "failed"}
                run_log["result"] = "failed"
                return run_log

            if not should_run:
                log_msg(f"[-] Step '{step_id}' skipped: condition '{condition_str}' evaluated to False")
                run_log["steps"][step_id] = {
                    "skipped": True,
                    "reason": f"Condition evaluated to False: {condition_str}",
                    "status": "skipped"
                }
                continue
            else:
                log_msg(f"[+] Step '{step_id}' condition '{condition_str}' evaluated to True")

        # Execute action dynamically
        if action_name not in ACTION_REGISTRY:
            err_msg = f"Action '{action_name}' is not registered in the engine."
            log_msg(f"[-] Step '{step_id}' failed: {err_msg}")
            run_log["steps"][step_id] = {"error": err_msg, "status": "failed"}
            run_log["result"] = "failed"
            return run_log

        action_func = ACTION_REGISTRY[action_name]

        # Dynamically map parameters depending on the action signature requirements
        try:
            result = None
            if action_name == "enrich_ip":
                ip = alert.get("indicator_value")
                result = action_func(ip)
                context["abuseConfidenceScore"] = result.get("abuseConfidenceScore", 0)
                context["enrichment"] = result
                if result.get("enrichment_failed"):
                    context["enrichment_failed"] = True
                    log_msg(f"[-] Enrichment failed for IP {ip}: {result.get('error_msg') or result.get('source')}")
                else:
                    context["enrichment_failed"] = False
                    log_msg(f"[+] Enriched IP {ip} -> Abuse confidence score: {context['abuseConfidenceScore']}%")

            elif action_name == "decide_severity":
                if context.get("enrichment_failed"):
                    result = {"severity": "enrichment_failed"}
                else:
                    thresholds = step.get("thresholds", {"critical": 75, "high": 50, "medium": 25, "low": 0})
                    result = action_func(context["abuseConfidenceScore"], thresholds)
                context["severity"] = result.get("severity", "low")
                log_msg(f"[+] Severity decided -> {context['severity'].upper()}")

            elif action_name == "contain_host":
                ip = alert.get("indicator_value")
                # Override playbook mode with command-line parameter if live mode is selected
                mode = "live" if contain_mode == "live" else step.get("mode", "dry_run")
                result = action_func(ip, mode=mode)
                log_msg(f"[+] Contain action status -> Executed: {result.get('executed')}, Note: {result.get('note')}")

            elif action_name == "open_ticket":
                severity = context["severity"]
                ip = alert.get("indicator_value")
                if severity == "enrichment_failed":
                    summary = (
                        f"Alert {alert.get('alert_id')} on host {alert.get('affected_host')}: "
                        f"enrichment failed for indicator {ip}. Flagged for manual review."
                    )
                elif severity == "unknown_requires_review":
                    summary = (
                        f"Alert {alert.get('alert_id')} on host {alert.get('affected_host')}: "
                        f"unknown/invalid score for indicator {ip}. Flagged for manual review."
                    )
                else:
                    summary = (
                        f"Alert {alert.get('alert_id')} on host {alert.get('affected_host')}: "
                        f"indicator {ip} scored {context.get('abuseConfidenceScore', 0)} "
                        f"(severity={severity})"
                    )
                result = action_func(alert.get("alert_id"), ip, severity, summary)
                context["ticket_id"] = result.get("ticket_id")
                context["ticket"] = result
                if result.get("merged"):
                    log_msg(f"[+] Duplicate alert detected -> Merged into existing Ticket ID: #{context['ticket_id']}")
                else:
                    log_msg(f"[+] Ticket opened -> Ticket ID: {context['ticket_id']}, Status: {result.get('status')}")

            elif action_name == "send_notification":
                severity = context["severity"]
                ip = alert.get("indicator_value")
                msg = (
                    f"[SOC ALERT] {severity.upper()} - {alert.get('alert_id')} "
                    f"| IP {ip} | score={context.get('abuseConfidenceScore', 0)} "
                    f"| ticket #{context.get('ticket_id')}"
                )
                result = action_func(msg)
                log_msg(f"[+] Notification sent -> Sent: {result.get('sent')}")

            # Save step output to logs
            result["status"] = "success"
            run_log["steps"][step_id] = result

        except Exception as e:
            log_msg(f"[-] Action '{action_name}' encountered an error: {e}")
            run_log["steps"][step_id] = {"error": str(e), "status": "failed"}
            run_log["result"] = "failed"
            return run_log

    run_log["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    run_log["result"] = "completed"
    log_msg(f"\n[+] Playbook run completed successfully.")
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

    try:
        alert = load_json(args.alert)
        playbook = load_yaml(args.playbook)
    except Exception as e:
        print(f"[-] Error loading input files: {e}")
        sys.exit(1)

    if args.live_contain:
        confirm = input("⚠️ WARNING: Live Containment is requested. This will execute real EDR/firewall actions. Proceed? (y/N): ")
        if confirm.lower().strip() != 'y':
            print("[-] Cancelled by user. Exiting.")
            sys.exit(0)

    mode = "live" if args.live_contain else "dry_run"

    run_log = run_playbook(alert, playbook, contain_mode=mode)
    log_path = save_run_log(run_log)

    print("\n" + "=" * 40)
    print(f"Playbook Execution Result Summary:")
    print("=" * 40)
    print(json.dumps(run_log, indent=2))
    print(f"\nRun log saved to: {log_path}")


if __name__ == "__main__":
    main()
