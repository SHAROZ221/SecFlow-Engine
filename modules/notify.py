"""
notify.py
Sends a Telegram message to the SOC channel/bot when the playbook
takes a meaningful action. Reuses the same bot-token/chat-id pattern
as MiniNIDS. Silently skips (prints instead) if not configured, so
the engine still runs end-to-end in a demo environment.
"""

import os
import requests


def send_notification(message: str) -> dict:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print(f"[notify - mock, no Telegram config] {message}")
        return {"sent": False, "note": "TELEGRAM_BOT_TOKEN/CHAT_ID not set, printed instead"}

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = requests.post(url, data={"chat_id": chat_id, "text": message}, timeout=10)
        resp.raise_for_status()
        return {"sent": True}
    except requests.RequestException as e:
        print(f"[notify - failed] {message} ({e})")
        return {"sent": False, "note": str(e)}
