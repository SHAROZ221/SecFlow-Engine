"""
webhook_notify.py
Sends notifications to Slack and Discord via incoming webhooks.
Each function loads the webhook URL from .env and returns a
standardised result dict: {"sent": bool, "channel": str, "note": str}.
"""

import os
import requests

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


def send_slack_webhook(message: str) -> dict:
    """Send a message to a Slack channel via incoming webhook.

    Returns:
        dict with keys: sent (bool), channel ("slack"), note (str).
    """
    _load_env()
    url = os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        return {"sent": False, "channel": "slack", "note": "SLACK_WEBHOOK_URL not configured"}

    try:
        resp = requests.post(url, json={"text": message}, timeout=10)
        resp.raise_for_status()
        return {"sent": True, "channel": "slack", "note": "Message delivered"}
    except requests.RequestException as e:
        return {"sent": False, "channel": "slack", "note": str(e)}


def send_discord_webhook(message: str) -> dict:
    """Send a message to a Discord channel via incoming webhook.

    Returns:
        dict with keys: sent (bool), channel ("discord"), note (str).
    """
    _load_env()
    url = os.getenv("DISCORD_WEBHOOK_URL")
    if not url:
        return {"sent": False, "channel": "discord", "note": "DISCORD_WEBHOOK_URL not configured"}

    try:
        resp = requests.post(url, json={"content": message}, timeout=10)
        resp.raise_for_status()
        return {"sent": True, "channel": "discord", "note": "Message delivered"}
    except requests.RequestException as e:
        return {"sent": False, "channel": "discord", "note": str(e)}
