"""
test_server_api.py
Verify the FastAPI backend endpoints, SQLite database, and playbook execution
using FastAPI's TestClient to run tests entirely in memory and deadlock-free.
"""

from fastapi.testclient import TestClient
import json
import time

# Import FastAPI app from server
from server import app

def test_flow():
    client = TestClient(app)

    print("[+] Step 1: Ingesting mock alert...")
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

    # Make POST request to trigger playbook
    response = client.post("/api/alerts", json=alert_payload)
    if response.status_code != 200:
        print(f"[-] Ingest alert failed: {response.text}")
        return False
        
    res = response.json()
    run_id = res.get("run_id")
    print(f"[+] Alert ingested successfully! Run ID: {run_id}")

    print("\n[+] Step 2: Waiting 2 seconds for playbook background execution to finish...")
    time.sleep(2)

    print("\n[+] Step 3: Fetching SQLite tickets queue...")
    response_tickets = client.get("/api/tickets")
    if response_tickets.status_code != 200:
        print(f"[-] Failed to fetch tickets: {response_tickets.text}")
        return False
        
    tickets = response_tickets.json()
    latest_ticket = tickets[0]
    ticket_id = latest_ticket.get("id")
    print(f"[+] Latest ticket in DB -> ID: #{ticket_id}, Alert: {latest_ticket.get('alert_id')}, Status: {latest_ticket.get('status')}")

    print(f"\n[+] Step 4: Resolving ticket #{ticket_id}...")
    response_resolve = client.post(f"/api/tickets/{ticket_id}/resolve")
    if response_resolve.status_code != 200:
        print(f"[-] Failed to resolve ticket: {response_resolve.text}")
        return False
        
    print(f"[+] Resolve API result: {response_resolve.json()}")

    print("\n[+] Step 5: Double checking ticket resolution status...")
    response_tickets_final = client.get("/api/tickets")
    if response_tickets_final.status_code != 200:
        print(f"[-] Failed to re-fetch tickets: {response_tickets_final.text}")
        return False
        
    tickets_final = response_tickets_final.json()
    checked_ticket = next(t for t in tickets_final if t["id"] == ticket_id)
    print(f"[+] Checked ticket #{ticket_id} status -> {checked_ticket.get('status')}")
    
    if checked_ticket.get("status") == "resolved":
        print("\n[++] ALL IN-MEMORY API TESTS PASSED SUCCESSFULLY! backend is fully operational.")
        return True
    else:
        print("[-] Ticket status is not resolved.")
        return False

if __name__ == "__main__":
    success = test_flow()
    import sys
    sys.exit(0 if success else 1)
