"""
containment.py
Generates the host/network containment action for a malicious IP.

SAFETY: mode="dry_run" (default) NEVER executes anything. It only
writes the command that WOULD be run to pending_actions.log, so this
is safe to demo without root or a real firewall. mode="live" will
actually attempt to run the iptables command -- only use this on a
lab box you control, and only if run with sufficient privileges.
"""

import subprocess
import datetime
import os

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "evidence", "pending_actions.log")


def contain_host(ip_address: str, mode: str = "dry_run") -> dict:
    command = f"iptables -A INPUT -s {ip_address} -j DROP"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    entry = f"[{timestamp}] MODE={mode} COMMAND: {command}\n"
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(entry)

    if mode == "dry_run":
        return {
            "executed": False,
            "command": command,
            "note": "Dry-run only. Command logged, not executed.",
        }

    # mode == "live" -- actually attempt to block. Requires root.
    try:
        subprocess.run(command.split(), check=True)
        return {"executed": True, "command": command, "note": "Executed successfully."}
    except Exception as e:
        return {"executed": False, "command": command, "note": f"Execution failed: {e}"}
