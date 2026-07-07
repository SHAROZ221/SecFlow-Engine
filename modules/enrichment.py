"""
enrichment.py
Looks up a source IP against AbuseIPDB to get an abuse confidence score,
country, ISP, and total reports. Falls back to a mock response if no
API key is configured, so the playbook is still demo-able without
live credentials.
"""

import os
import requests

try:
    import dotenv
except ImportError:
    dotenv = None

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def enrich_ip(ip_address: str) -> dict:
    if dotenv:
        # Load .env file relative to this file's parent folder
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if os.path.exists(env_path):
            dotenv.load_dotenv(env_path, override=True)
            
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        # Safe fallback so the engine still runs end-to-end without a key
        return {
            "ip": ip_address,
            "abuseConfidenceScore": 0,
            "countryCode": "N/A",
            "isp": "N/A",
            "totalReports": 0,
            "source": "mock (no ABUSEIPDB_API_KEY set)",
        }

    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip": ip_address,
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "countryCode": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "totalReports": data.get("totalReports", 0),
            "source": "AbuseIPDB (live)",
        }
    except requests.RequestException as e:
        return {
            "ip": ip_address,
            "abuseConfidenceScore": 0,
            "countryCode": "N/A",
            "isp": "N/A",
            "totalReports": 0,
            "source": f"error: {e}",
        }
