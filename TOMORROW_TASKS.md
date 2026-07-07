# Tomorrow's Tasks - SecFlow Engine

This document outlines the plans and task options for the next development session. We will select one of the core options below to implement next.

---

## 🎯 Select Next Milestone

### 🔌 Option A: Live API Integrations & Settings Panel
*   **Goal:** Allow analysts to input actual API keys and webhook links to connect the pipeline to live external security resources.
*   **Tasks:**
    - [ ] Create a settings gear icon and overlay modal in the frontend dashboard.
    - [ ] Add an endpoint `POST /api/settings` to write keys securely to a local `.env` file.
    - [ ] Update `modules/enrichment.py` to make live AbuseIPDB queries if the key exists.
    - [ ] Update `modules/notify.py` to send custom alert blocks to a configured Slack/Discord webhook.

### 📄 Option B: Automated Incident Response Exporter
*   **Goal:** Automate compliance documentation by compiling incident summaries into downloadable reports.
*   **Tasks:**
    - [ ] Write `modules/report_generator.py` to aggregate alert details, Threat Intel scores, EDR action logs, and ticket comments.
    - [ ] Integrate a report compiler to generate Markdown or PDF files.
    - [ ] Add an "Export Report 📄" button on the Ticketing Center table rows.

### 🖥️ Option C: Simulated EDR Host Agent (`agent.py`)
*   **Goal:** Demonstrate host containment live on a simulated client workstation.
*   **Tasks:**
    - [ ] Create `agent.py` to run as a separate client script that heartbeats with the FastAPI server.
    - [ ] Setup dashboard views of registered hosts, their status (Active / Isolated), and connection timers.
    - [ ] Hook EDR containment step to trigger a client command simulating local connection blocks.
