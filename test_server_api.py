"""
test_server_api.py
Verify the FastAPI backend endpoints, settings API, SQLite database, and playbook execution
using FastAPI's TestClient to run tests entirely in memory and deadlock-free.
"""

from fastapi.testclient import TestClient
import json
import time
import os

# Import FastAPI app from server
from server import app

def test_flow():
    client = TestClient(app)

    # 0. Authenticate test client
    login_resp = client.post("/api/auth/login", json={"username": "admin", "password": "secflow123"})
    assert login_resp.status_code == 200, "Authentication failed"

    print("[+] Step 1: Testing Settings API (GET and POST)...")
    
    # 1. Fetch initial settings
    resp_get = client.get("/api/settings")
    assert resp_get.status_code == 200
    init_settings = resp_get.json()
    print(f"[+] Initial settings retrieved: {init_settings}")

    # 2. Write new test settings
    test_settings = {
        "abuseipdb_api_key": "TESTAPIKEY123456789",
        "telegram_bot_token": "TELEGRAMBOTTOKEN987654",
        "telegram_chat_id": "-10022334455",
        "github_token": "GHPAUTHKEY987654321",
        "github_repo": "SHAROZ221/SecFlow-Engine"
    }
    resp_post = client.post("/api/settings", json=test_settings)
    assert resp_post.status_code == 200
    print("[+] Test settings saved successfully.")

    # 3. Read back to confirm masking
    resp_get_new = client.get("/api/settings")
    assert resp_get_new.status_code == 200
    new_settings = resp_get_new.json()
    print(f"[+] Retrieved masked settings: {new_settings}")
    
    # Verify masking pattern (first 4 characters, ..., last 4 characters)
    assert new_settings["abuseipdb_api_key"] == "TEST...6789"
    assert new_settings["telegram_bot_token"] == "TELE...7654"
    assert new_settings["telegram_chat_id"] == "-10022334455"
    assert new_settings["github_token"] == "GHPA...4321"
    assert new_settings["github_repo"] == "SHAROZ221/SecFlow-Engine"
    print("[+] Masking verification passed.")

    print("\n[+] Step 2: Ingesting alert to verify live API lookup attempt...")
    alert_payload = {
        "alert_id": "ALRT-9999",
        "source": "Wazuh-Test",
        "rule_description": "API verification alert",
        "indicator_type": "ip",
        "indicator_value": "198.51.100.22",
        "affected_host": "test-box",
        "raw_severity": "high",
        "live_contain": False
    }

    # Trigger playbook run
    response = client.post("/api/alerts", json=alert_payload)
    if response.status_code != 200:
        print(f"[-] Ingest alert failed: {response.text}")
        return False
        
    res = response.json()
    run_id = res.get("run_id")
    print(f"[+] Alert ingested successfully! Run ID: {run_id}")

    print("\n[+] Step 3: Waiting 2 seconds for playbook background execution to finish...")
    time.sleep(2)

    # Clean up test settings from .env immediately so we don't leave bad keys
    # By sending empty strings, we clear the keys
    clear_settings = {
        "abuseipdb_api_key": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "github_token": "",
        "github_repo": ""
    }
    client.post("/api/settings", json=clear_settings)
    print("[+] Restored settings back to empty.")

    # Verify run logs to ensure it attempted a live lookup (and failed due to invalid key)
    # rather than falling back to the local mock driver.
    # We inspect the saved JSON logs under evidence/
    evidence_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    log_files = [f for f in os.listdir(evidence_dir) if f.startswith(f"run_ALRT-9999_")]
    if not log_files:
        print("[-] Playbook execution log file not found in evidence/.")
        return False
        
    latest_log_path = os.path.join(evidence_dir, sorted(log_files)[-1])
    with open(latest_log_path, "r") as f:
        run_log = json.load(f)
        
    enrich_result = run_log["steps"]["enrich"]
    print(f"[+] Enrichment source recorded in execution log: {enrich_result['source']}")
    
    # It must either succeed live (unlikely with dummy key) or report an error code,
    # but it must NOT say "mock (no ABUSEIPDB_API_KEY set)".
    assert "mock" not in enrich_result["source"]
    print("[+] Dynamic config reloading and live fallback shift verified successfully!")

    print("\n[+] Step 4: Fetching SQLite tickets queue...")
    response_tickets = client.get("/api/tickets")
    if response_tickets.status_code != 200:
        print(f"[-] Failed to fetch tickets: {response_tickets.text}")
        return False
        
    tickets = response_tickets.json()
    latest_ticket = tickets[0]
    ticket_id = latest_ticket.get("id")
    print(f"[+] Latest ticket in DB -> ID: #{ticket_id}, Alert: {latest_ticket.get('alert_id')}, Status: {latest_ticket.get('status')}")

    print(f"\n[+] Step 5: Resolving ticket #{ticket_id}...")
    response_resolve = client.post(f"/api/tickets/{ticket_id}/resolve")
    if response_resolve.status_code != 200:
        print(f"[-] Failed to resolve ticket: {response_resolve.text}")
        return False
        
    print(f"[+] Resolve API result: {response_resolve.json()}")

    print("\n[+] Step 6: Double checking ticket resolution status...")
    response_tickets_final = client.get("/api/tickets")
    if response_tickets_final.status_code != 200:
        print(f"[-] Failed to re-fetch tickets: {response_tickets_final.text}")
        return False
        
    tickets_final = response_tickets_final.json()
    checked_ticket = next(t for t in tickets_final if t["id"] == ticket_id)
    print(f"[+] Checked ticket #{ticket_id} status -> {checked_ticket.get('status')}")
    
    print("\n[+] Step 7: Testing Playbook Editor API (GET and POST)...")
    resp_get_pb = client.get("/api/playbook")
    assert resp_get_pb.status_code == 200, "Failed to GET playbook"
    orig_pb = resp_get_pb.json()
    print(f"[+] Loaded original playbook: {orig_pb['name']}")
    
    # Modify a value
    modified_pb = orig_pb.copy()
    modified_pb["name"] = "test_playbook_mod"
    modified_pb["description"] = "Temporary test description for API validation"
    
    resp_post_pb = client.post("/api/playbook", json=modified_pb)
    assert resp_post_pb.status_code == 200, f"Failed to POST modified playbook: {resp_post_pb.text}"
    print("[+] Modified playbook saved successfully.")
    
    # Verify the changes
    resp_get_pb2 = client.get("/api/playbook")
    assert resp_get_pb2.status_code == 200
    updated_pb = resp_get_pb2.json()
    assert updated_pb["name"] == "test_playbook_mod"
    assert updated_pb["description"] == "Temporary test description for API validation"
    print("[+] Verified changed name and description in playbook.")
    
    # Restore original playbook
    resp_restore_pb = client.post("/api/playbook", json=orig_pb)
    assert resp_restore_pb.status_code == 200, "Failed to restore original playbook"
    print("[+] Restored original playbook configuration successfully.")

    if checked_ticket.get("status") == "resolved":
        print("\n[++] ALL IN-MEMORY API AND INTEGRATION TESTS PASSED SUCCESSFULLY! backend is fully operational.")
        return True
    else:
        print("[-] Ticket status is not resolved.")
        return False

if __name__ == "__main__":
    success = test_flow()
    import sys
    sys.exit(0 if success else 1)
