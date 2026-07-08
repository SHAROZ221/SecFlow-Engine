"""
server.py
FastAPI web server for the SOAR-Playbook dashboard.
Provides API endpoints to ingest alerts, trigger dynamic playbooks,
stream execution logs in real time using SSE, and manage tickets.
"""

import os
import uuid
import json
import sqlite3
import asyncio
import threading
import hashlib
import secrets
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request, Response, Cookie
from fastapi.responses import StreamingResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    dotenv = None

from main import run_playbook, load_yaml, save_run_log

app = FastAPI(title="SOAR-Playbook Dashboard")

class SettingsPayload(BaseModel):
    abuseipdb_api_key: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

class LoginPayload(BaseModel):
    username: str
    password: str

# Simple in-memory session store
active_sessions = set()

# Helper: Hash password
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

# Helper: Get authentication credentials from .env
def get_auth_credentials():
    if dotenv and os.path.exists(ENV_PATH):
        dotenv.load_dotenv(ENV_PATH, override=True)
    admin_user = os.getenv("ADMIN_USER", "admin")
    # Default password hash for 'secflow123' if not set in .env
    default_hash = hash_password("secflow123")
    admin_pass_hash = os.getenv("ADMIN_PASSWORD_HASH", default_hash)
    return admin_user, admin_pass_hash


# Enable CORS for development convenience
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory dictionary to hold Server-Sent Events (SSE) queues for active runs
active_runs = {}

# Directory paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
PLAYBOOK_PATH = os.path.join(BASE_DIR, "playbook.yaml")
DB_PATH = os.path.join(BASE_DIR, "evidence", "tickets.db")
ENV_PATH = os.path.join(BASE_DIR, ".env")

def get_env_settings():
    if dotenv and os.path.exists(ENV_PATH):
        dotenv.load_dotenv(ENV_PATH, override=True)
    
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    tg_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    tg_chat = os.getenv("TELEGRAM_CHAT_ID", "")
    
    def mask_key(k):
        if not k:
            return ""
        if len(k) <= 8:
            return "********"
        return f"{k[:4]}...{k[-4:]}"
        
    return {
        "abuseipdb_api_key": mask_key(abuse_key),
        "telegram_bot_token": mask_key(tg_token),
        "telegram_chat_id": tg_chat,
    }

def write_env_settings(payload: SettingsPayload):
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            lines = f.readlines()
            
    env_dict = {}
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env_dict[k.strip()] = v.strip()
            
    new_abuse = payload.abuseipdb_api_key.strip()
    if new_abuse and "..." not in new_abuse:
        env_dict["ABUSEIPDB_API_KEY"] = new_abuse
    elif not new_abuse:
        env_dict.pop("ABUSEIPDB_API_KEY", None)
        
    new_tg_token = payload.telegram_bot_token.strip()
    if new_tg_token and "..." not in new_tg_token:
        env_dict["TELEGRAM_BOT_TOKEN"] = new_tg_token
    elif not new_tg_token:
        env_dict.pop("TELEGRAM_BOT_TOKEN", None)
        
    new_tg_chat = payload.telegram_chat_id.strip()
    if new_tg_chat:
        env_dict["TELEGRAM_CHAT_ID"] = new_tg_chat
    else:
        env_dict.pop("TELEGRAM_CHAT_ID", None)
        
    with open(ENV_PATH, "w") as f:
        for k, v in env_dict.items():
            f.write(f"{k}={v}\n")
            
    if dotenv:
        dotenv.load_dotenv(ENV_PATH, override=True)


class AlertPayload(BaseModel):
    alert_id: str
    source: str
    rule_description: str
    indicator_type: str
    indicator_value: str
    affected_host: str
    raw_severity: str = "high"
    live_contain: bool = False


# Helper: Initialize SQLite DB (ensures database exists)
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            indicator TEXT,
            severity TEXT,
            status TEXT,
            created_at TEXT,
            summary TEXT
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


# Background task wrapper that executes the playbook
def execute_playbook_bg(alert: dict, playbook: dict, contain_mode: str, log_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    def log_callback(msg: str):
        # Thread-safe write to the asyncio queue
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, msg)

    try:
        run_log = run_playbook(alert, playbook, contain_mode=contain_mode, log_callback=log_callback)
        save_run_log(run_log)
        # Send completed tag with stringified JSON run_log
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, f"__COMPLETED__:{json.dumps(run_log)}")
    except Exception as e:
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, f"__FAILED__:Error running playbook: {e}")
    finally:
        # Send None to indicate end of queue
        if not loop.is_closed():
            loop.call_soon_threadsafe(log_queue.put_nowait, None)


# Helper: Validate Session
def get_session_user(session_id: str = Cookie(None)) -> str:
    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=401, detail="Unauthorized session")
    return "admin"

@app.get("/login")
def login_page():
    login_path = os.path.join(WEB_DIR, "login.html")
    if not os.path.exists(login_path):
        raise HTTPException(status_code=404, detail="Login page not found.")
    return FileResponse(login_path)

@app.post("/api/auth/login")
def login_api(payload: LoginPayload, response: Response):
    expected_user, expected_hash = get_auth_credentials()
    if payload.username != expected_user or hash_password(payload.password) != expected_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    session_id = str(uuid.uuid4())
    active_sessions.add(session_id)
    # Set standard session cookie (lasts for session length)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False  # Allow HTTP in local dev
    )
    return {"status": "success"}

@app.post("/api/auth/logout")
def logout_api(response: Response, session_id: str = Cookie(None)):
    if session_id in active_sessions:
        active_sessions.remove(session_id)
    response.delete_cookie(key="session_id")
    return {"status": "success"}

@app.get("/api/auth/me")
def check_auth(session_id: str = Cookie(None)):
    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"username": "admin"}

@app.get("/")
def read_root(session_id: str = Cookie(None)):
    """Serves the dashboard HTML interface if authenticated, else redirects to login."""
    if not session_id or session_id not in active_sessions:
        return RedirectResponse(url="/login")
        
    index_path = os.path.join(WEB_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Dashboard frontend (web/index.html) not found.")
    return FileResponse(index_path)


# Static stylesheet route
@app.get("/css/styles.css")
def read_css():
    css_path = os.path.join(WEB_DIR, "css", "styles.css")
    if not os.path.exists(css_path):
        raise HTTPException(status_code=404, detail="Stylesheet not found.")
    return FileResponse(css_path, media_type="text/css")


from fastapi import Depends

@app.post("/api/alerts")
async def trigger_playbook_endpoint(payload: AlertPayload, background_tasks: BackgroundTasks, user: str = Depends(get_session_user)):
    """
    Ingests a new alert, loads the default playbook,
    and spins up a background thread to run the playbook.
    """
    try:
      playbook = load_yaml(PLAYBOOK_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load playbook.yaml: {e}")

    alert_dict = payload.model_dump()
    contain_mode = "live" if payload.live_contain else "dry_run"

    # Generate execution run ID
    run_id = str(uuid.uuid4())
    log_queue = asyncio.Queue()
    active_runs[run_id] = log_queue

    # Start thread running the playbook
    loop = asyncio.get_running_loop()
    threading.Thread(
        target=execute_playbook_bg,
        args=(alert_dict, playbook, contain_mode, log_queue, loop),
        daemon=True
    ).start()

    return {"run_id": run_id}


@app.get("/api/runs/{run_id}/stream")
def stream_run_logs(run_id: str, user: str = Depends(get_session_user)):
    """
    Streams playbook execution output as Server-Sent Events (SSE).
    """
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail="Execution stream not found.")

    log_queue = active_runs[run_id]

    async def event_generator():
        try:
            while True:
                msg = await log_queue.get()
                if msg is None:
                    break
                yield f"data: {msg}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            # Clean up queue when client disconnects or finishes
            active_runs.pop(run_id, None)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/tickets")
def list_tickets(user: str = Depends(get_session_user)):
    """Returns all open and resolved tickets in the SQLite queue."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM tickets ORDER BY id DESC")
        tickets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return tickets
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


@app.post("/api/tickets/{ticket_id}/resolve")
def resolve_ticket(ticket_id: int, user: str = Depends(get_session_user)):
    """Marks a ticket as resolved."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("UPDATE tickets SET status = 'resolved' WHERE id = ?", (ticket_id,))
        conn.commit()
        changes = cursor.rowcount
        conn.close()
        if changes == 0:
            raise HTTPException(status_code=404, detail="Ticket not found.")
        return {"status": "success", "resolved_id": ticket_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

import io
import csv
from datetime import datetime

# Helper to scan and load run logs
def load_all_run_logs():
    logs = []
    evidence_dir = os.path.join(BASE_DIR, "evidence")
    if not os.path.exists(evidence_dir):
        return logs
    for fname in os.listdir(evidence_dir):
        if fname.startswith("run_") and fname.endswith(".json"):
            path = os.path.join(evidence_dir, fname)
            try:
                with open(path, "r") as f:
                    log_data = json.load(f)
                    logs.append(log_data)
            except Exception:
                pass
    # Sort by started_at descending
    logs.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    return logs

@app.get("/api/threats")
def get_threats(user: str = Depends(get_session_user)):
    """Returns a list of threat indicators extracted from past run logs."""
    run_logs = load_all_run_logs()
    threats = []
    seen = set() # Avoid listing the exact same run log details multiple times if duplicated
    for r in run_logs:
        enrich = r.get("steps", {}).get("enrich", {})
        ip = enrich.get("ip")
        if not ip:
            continue
        
        decide = r.get("steps", {}).get("decide", {})
        severity = decide.get("severity", "low")
        started_at = r.get("started_at", "")
        
        # Unique threat entry for this run log
        run_id = r.get("alert_id", "") + "_" + started_at
        if run_id in seen:
            continue
        seen.add(run_id)
        
        threats.append({
            "alert_id": r.get("alert_id"),
            "started_at": started_at,
            "ip": ip,
            "score": enrich.get("abuseConfidenceScore", 0),
            "country": enrich.get("countryCode", "N/A"),
            "isp": enrich.get("isp", "N/A"),
            "severity": severity,
            "status": r.get("result", "unknown")
        })
    return threats

@app.get("/api/network-stats")
def get_network_stats(user: str = Depends(get_session_user)):
    """Returns aggregated country/ISP counts and threat summaries for Network view."""
    run_logs = load_all_run_logs()
    countries = {}
    isps = {}
    unique_ips = set()
    total_score = 0
    score_count = 0
    
    for r in run_logs:
        enrich = r.get("steps", {}).get("enrich", {})
        ip = enrich.get("ip")
        if not ip:
            continue
        unique_ips.add(ip)
        
        c = enrich.get("countryCode", "N/A")
        countries[c] = countries.get(c, 0) + 1
        
        isp = enrich.get("isp", "N/A")
        if isp != "N/A":
            isps[isp] = isps.get(isp, 0) + 1
            
        score = enrich.get("abuseConfidenceScore")
        if score is not None:
            total_score += score
            score_count += 1
            
    # Format countries breakdown
    total_ips = len(run_logs)
    country_list = []
    for code, count in countries.items():
        pct = round((count / total_ips) * 100) if total_ips > 0 else 0
        country_list.append({"code": code, "count": count, "percentage": pct})
    country_list.sort(key=lambda x: x["count"], reverse=True)
    
    # Format top ISPs breakdown
    isp_list = [{"name": name, "count": count} for name, count in isps.items()]
    isp_list.sort(key=lambda x: x["count"], reverse=True)
    
    avg_score = round(total_score / score_count) if score_count > 0 else 0
    
    return {
        "total_ips": len(unique_ips),
        "countries": country_list[:6], # Top 6
        "isps": isp_list[:6],          # Top 6
        "avg_score": avg_score
    }

@app.get("/api/assets")
def get_assets(user: str = Depends(get_session_user)):
    """Returns list of unique assets (affected hosts) and their status."""
    # We combine alert host info from run logs and SQLite DB
    run_logs = load_all_run_logs()
    assets = {}
    
    # Fetch from SQLite first to seed the asset status
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM tickets")
        tickets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        for t in tickets:
            host_display = "N/A"
            if t.get("summary") and "host " in t["summary"]:
                try:
                    host_display = t["summary"].split("host ")[1].split(":")[0]
                except Exception:
                    pass
            if host_display != "N/A":
                assets[host_display] = {
                    "hostname": host_display,
                    "ip": t.get("indicator", "N/A"),
                    "status": "Active (No Isolation)",
                    "alert_ids": [t.get("alert_id")],
                    "last_seen": t.get("created_at")
                }
    except Exception:
        pass
        
    # Overlay with run log details
    for r in run_logs:
        enrich = r.get("steps", {}).get("enrich", {})
        ip = enrich.get("ip", "N/A")
        # In this lite SOAR engine, the host is not always explicitly logged inside run_log top-level,
        # but we can look for it in the containment step details or just fallback to tickets.
        # However, let's look at containment details:
        contain = r.get("steps", {}).get("contain", {})
        
        # Let's see if we have alert_id, let's grab host from ticket if available, or just map hosts
        # Actually, let's extract host if it was in the alert payload
        # Wait, run_*.json doesn't save the full alert payload directly, but we can search for it.
        # Let's extract host name if containment command details exist:
        cmd = contain.get("command", "")
        host = "N/A"
        if "isolate" in cmd:
            parts = cmd.split("isolate ")
            if len(parts) > 1:
                host = parts[1].strip()
        elif "dry-run" in cmd:
            parts = cmd.split("dry-run isolate ")
            if len(parts) > 1:
                host = parts[1].strip()
                
        if host == "N/A":
            continue
            
        status = "Active (No Isolation)"
        if contain.get("status") == "success":
            status = "Isolated (Live)"
        elif contain.get("status") == "skipped" and "Condition evaluated to False" not in contain.get("reason", ""):
            status = "Monitoring"
        elif contain.get("status") == "success" or "dry-run" in cmd:
            status = "Dry Run (Isolated)"
            
        if host in assets:
            assets[host]["status"] = status
            assets[host]["ip"] = ip
            if r.get("alert_id") not in assets[host]["alert_ids"]:
                assets[host]["alert_ids"].append(r.get("alert_id"))
        else:
            assets[host] = {
                "hostname": host,
                "ip": ip,
                "status": status,
                "alert_ids": [r.get("alert_id")],
                "last_seen": r.get("started_at")
            }
            
    # Default fallbacks for clean asset views
    if not assets:
        assets["web-srv-03"] = {
            "hostname": "web-srv-03",
            "ip": "185.220.101.45",
            "status": "Active (No Isolation)",
            "alert_ids": ["ALRT-1042"],
            "last_seen": datetime.now().isoformat()
        }
        
    return list(assets.values())

@app.get("/api/runs")
def get_compliance_runs(user: str = Depends(get_session_user)):
    """Returns metadata of all past playbook runs for Compliance view."""
    run_logs = load_all_run_logs()
    runs = []
    for r in run_logs:
        started = r.get("started_at", "")
        finished = r.get("finished_at", "")
        duration_sec = 0
        if started and finished:
            try:
                # Replace ':' in timezone offset or handle ISO parse
                s_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                f_dt = datetime.fromisoformat(finished.replace("Z", "+00:00"))
                duration_sec = round((f_dt - s_dt).total_seconds(), 2)
            except Exception:
                duration_sec = 0.02 # default visual fallback
                
        runs.append({
            "alert_id": r.get("alert_id"),
            "started_at": started,
            "playbook": r.get("playbook", "malicious_ip_response"),
            "result": r.get("result", "completed"),
            "duration": duration_sec
        })
    return runs

@app.get("/api/export/tickets")
def export_tickets(user: str = Depends(get_session_user)):
    """Generates and downloads SQLite ticket queue database records as a CSV file."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM tickets ORDER BY id DESC")
        tickets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow(["Ticket ID", "Alert ID", "Indicator (IP)", "Severity", "Status", "Created At", "Summary"])
        
        for t in tickets:
            writer.writerow([
                f"#{t['id']}",
                t.get("alert_id", ""),
                t.get("indicator", ""),
                t.get("severity", ""),
                t.get("status", ""),
                t.get("created_at", ""),
                t.get("summary", "")
            ])
            
        csv_data = output.getvalue()
        response = Response(content=csv_data, media_type="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=secflow_tickets_export.csv"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {e}")

@app.get("/api/export/runs")
def export_runs(user: str = Depends(get_session_user)):
    """Generates and downloads Playbook execution history logs as a CSV file."""
    try:
        run_logs = load_all_run_logs()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow(["Alert ID", "Playbook", "Started At", "Finished At", "Indicator (IP)", "Severity", "Abuse Score", "ISP", "Country", "Result"])
        
        for r in run_logs:
            enrich = r.get("steps", {}).get("enrich", {})
            decide = r.get("steps", {}).get("decide", {})
            writer.writerow([
                r.get("alert_id", ""),
                r.get("playbook", ""),
                r.get("started_at", ""),
                r.get("finished_at", ""),
                enrich.get("ip", ""),
                decide.get("severity", ""),
                enrich.get("abuseConfidenceScore", 0),
                enrich.get("isp", ""),
                enrich.get("countryCode", ""),
                r.get("result", "")
            ])
            
        csv_data = output.getvalue()
        response = Response(content=csv_data, media_type="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=secflow_playbook_runs_export.csv"
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {e}")

@app.get("/api/settings")
def get_settings(user: str = Depends(get_session_user)):
    """Returns masked credentials stored in the local .env configuration."""
    try:
        return get_env_settings()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read settings: {e}")

@app.post("/api/settings")
def save_settings(payload: SettingsPayload, user: str = Depends(get_session_user)):
    """Saves credentials securely to .env and updates the current environment."""
    try:
        write_env_settings(payload)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)

