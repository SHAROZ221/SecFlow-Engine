# SOAR-Lite Playbook Engine

A lightweight SOAR (Security Orchestration, Automation & Response)
playbook engine that automates the repetitive first steps of SOC alert
triage: **enrich → decide → contain → ticket → notify**.

Built to mirror how real tools (Splunk SOAR, Shuffle, Tines) work:
playbooks are defined declaratively in YAML, and a Python engine
executes the steps against incoming alerts.

## Why this exists

Most SOC alert triage follows the same manual pattern: check the IP
reputation, decide if it's serious, maybe block it, log a ticket,
tell the team. This project automates that pipeline end-to-end so an
analyst only has to review/approve instead of doing each step by hand.

## Architecture

```
Alert (JSON) --> Playbook Engine (main.py) --> playbook.yaml (defines steps)
                        |
        +---------------+----------------+------------------+
        |               |                |                  |
   enrichment.py   containment.py   ticketing.py         notify.py
   (AbuseIPDB)      (dry-run/live)   (SQLite ticket        (Telegram)
                                       queue)
```

## Flow

1. **Enrich** — looks up the alert's source IP against AbuseIPDB
   (abuse confidence score, ISP, country, report count).
2. **Decide** — maps the abuse score to a severity: `critical`
   (>=75), `medium` (>=25), or `low`.
3. **Contain** — for `critical` alerts, generates the host block
   command. **Dry-run by default** — it logs the command it *would*
   run rather than executing it. A `--live-contain` flag exists for
   lab environments where you actually want it to run.
4. **Ticket** — opens a ticket in a local SQLite queue for every
   alert that reaches this stage, regardless of severity.
5. **Notify** — sends a Telegram alert for `critical`/`medium`
   severities.

Every run produces a JSON run-log under `evidence/` documenting each
step's input/output — useful as an audit trail and as proof-of-work
evidence for your portfolio/interview.

## Setup

```bash
pip install -r requirements.txt
```

Optional environment variables (the engine runs fine without them,
using safe mock fallbacks):

```bash
export ABUSEIPDB_API_KEY="your_key_here"
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

## Usage

```bash
python main.py --alert sample_alerts/sample_alert_malicious_ip.json
```

To actually execute containment (lab environments only, needs root):

```bash
python main.py --alert sample_alerts/sample_alert_malicious_ip.json --live-contain
```

## Honest scope (what this is and isn't)

- Containment is **dry-run by default and intentionally not wired to
  a real firewall/EDR** in this repo — it's a safe demonstration of
  the decision + action logic, not a production containment tool.
  If you later test `--live-contain` against a real iptables rule in
  your own lab, note that specifically as "tested live in an isolated
  lab VM" rather than implying it's production-hardened.
- Ticketing uses a local SQLite queue as a stand-in for a real system
  (Jira/ServiceNow/GLPI). Swapping `ticketing.py` for an API call is
  the natural next step if you want to demo real integration.
- Enrichment is real and live if you provide an AbuseIPDB key.

## Possible extensions

- Add a second playbook (e.g., phishing email triage: enrich sender
  domain, check attachment hash against VirusTotal, quarantine
  mailbox).
- Swap SQLite ticketing for a real Jira/GLPI API call.
- Add a Flask dashboard to view run logs and pending containment
  actions (matches the dashboard pattern from your other projects).
- Wire `--live-contain` into a real isolated lab VM and capture
  evidence screenshots, same as you did for MiniNIDS.

## Tech stack

Python, PyYAML, Requests, SQLite, AbuseIPDB API, Telegram Bot API.
