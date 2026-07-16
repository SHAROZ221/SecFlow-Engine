"""
jira_integration.py
Creates Jira issues via the Atlassian REST API v3 for high/critical
SecFlow incidents. Requires JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN,
and JIRA_PROJECT_KEY to be set in the project .env file.
"""

import os
import requests
from requests.auth import HTTPBasicAuth

try:
    import dotenv
except ImportError:
    dotenv = None


def _load_env():
    """Load .env from project root if dotenv is available."""
    if dotenv:
        env_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
        )
        if os.path.exists(env_path):
            dotenv.load_dotenv(env_path, override=True)


_PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def create_jira_issue(alert_id: str, indicator: str, severity: str, summary: str) -> dict:
    """Create a Jira issue for the given SecFlow incident.

    Args:
        alert_id: SecFlow alert identifier.
        indicator: The threat indicator (e.g. IP address).
        severity: Severity level string (critical/high/medium/low).
        summary: Human-readable incident summary.

    Returns:
        dict with keys: created (bool), issue_key (str|None),
        issue_url (str|None), note (str).
    """
    _load_env()

    jira_url = os.getenv("JIRA_BASE_URL")
    jira_email = os.getenv("JIRA_EMAIL")
    jira_token = os.getenv("JIRA_API_TOKEN")
    jira_project = os.getenv("JIRA_PROJECT_KEY")

    if not all([jira_url, jira_email, jira_token, jira_project]):
        return {"created": False, "note": "Jira not configured"}

    api_endpoint = f'{jira_url.rstrip("/")}/rest/api/3/issue'

    description_text = (
        f"SecFlow Incident Report\n\n"
        f"Alert ID: {alert_id}\n"
        f"Indicator (IP): {indicator}\n"
        f"Severity: {severity.upper()}\n\n"
        f"{summary}"
    )

    payload = {
        "fields": {
            "project": {"key": jira_project},
            "summary": f"[SecFlow] {severity.upper()} - {alert_id} | IP {indicator}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description_text}],
                    }
                ],
            },
            "issuetype": {"name": "Task"},
            "priority": {"name": _PRIORITY_MAP.get(severity.lower(), "Medium")},
        }
    }

    try:
        resp = requests.post(
            api_endpoint,
            json=payload,
            auth=HTTPBasicAuth(jira_email, jira_token),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        issue_key = data.get("key", "")
        issue_url = f'{jira_url.rstrip("/")}/browse/{issue_key}'
        return {"created": True, "issue_key": issue_key, "issue_url": issue_url, "note": "Issue created"}
    except requests.RequestException as e:
        return {"created": False, "note": f"Jira API error: {e}"}
