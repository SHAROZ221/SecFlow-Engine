"""
notify.py
Sends notifications to configured channels: Telegram, Slack, and Discord.
Reuses the same bot-token/chat-id pattern for Telegram, plus Slack and
Discord incoming webhooks. Silently skips (prints instead) if not configured,
so the engine still runs end-to-end in a demo environment.
"""

import os
import requests

try:
    import dotenv
except ImportError:
    dotenv = None


def send_notification(message: str) -> dict:
    if dotenv:
        # Load .env file relative to this file's parent folder
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if os.path.exists(env_path):
            dotenv.load_dotenv(env_path, override=True)

    results = {}

    # Telegram
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    if token and chat_id:
        url = f'https://api.telegram.org/bot{token}/sendMessage'
        try:
            resp = requests.post(url, data={'chat_id': chat_id, 'text': message}, timeout=10)
            resp.raise_for_status()
            results['telegram'] = {'sent': True}
        except requests.RequestException as e:
            print(f'[notify - telegram failed] {message} ({e})')
            results['telegram'] = {'sent': False, 'note': str(e)}
    else:
        print(f'[notify - mock, no Telegram config] {message}')
        results['telegram'] = {'sent': False, 'note': 'TELEGRAM not configured'}

    # Slack
    slack_url = os.getenv('SLACK_WEBHOOK_URL')
    if slack_url:
        try:
            resp = requests.post(slack_url, json={'text': message}, timeout=10)
            resp.raise_for_status()
            results['slack'] = {'sent': True}
        except requests.RequestException as e:
            print(f'[notify - slack failed] ({e})')
            results['slack'] = {'sent': False, 'note': str(e)}

    # Discord
    discord_url = os.getenv('DISCORD_WEBHOOK_URL')
    if discord_url:
        try:
            resp = requests.post(discord_url, json={'content': message}, timeout=10)
            resp.raise_for_status()
            results['discord'] = {'sent': True}
        except requests.RequestException as e:
            print(f'[notify - discord failed] ({e})')
            results['discord'] = {'sent': False, 'note': str(e)}

    # Overall sent flag (True if ANY channel succeeded)
    any_sent = any(ch.get('sent') for ch in results.values())
    results['sent'] = any_sent
    return results
