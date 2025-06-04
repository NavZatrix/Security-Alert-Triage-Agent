import sqlite3, json, datetime

# Initialize persistent SQLite database (alerts log) and in-memory cache.
conn = sqlite3.connect('alerts.db')  # using a file for persistence; use ':memory:' for pure memory
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS alerts_log (
    id TEXT,            -- could be alert ID or batch job ID
    action TEXT,        -- e.g., classification, escalation, routing, etc.
    detail TEXT,        -- JSON string of additional details (severity, decisions, reasons)
    timestamp TEXT
)''')
conn.commit()

# In-memory cache to store live (unresolved) alerts and their status.
live_alerts = {}

# Governance policy parameters
agent_token_present = True
agent_clearance_level = 4        # starting clearance (will be changed during simulation)
REQUIRED_CLEARANCE = 5           # clearance needed for high-severity escalation

# Decision log list (for output or further processing)
decision_logs = []

def log_decision(alert_id, action, detail):
    """Log a decision/action with details to both the in-memory list and SQLite."""
    entry = {
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "alert_id": str(alert_id),
        "action": action
    }
    # If detail is a dict, merge it into the log entry; if it's a simple string, record it.
    if isinstance(detail, dict):
        entry.update(detail)
    else:
        entry["detail"] = detail
    decision_logs.append(entry)
    # Store in the SQL log (as JSON text for detail for simplicity)
    c.execute("INSERT INTO alerts_log VALUES (?, ?, ?, ?)", 
              (str(alert_id), action, json.dumps(detail), entry["timestamp"]))
    conn.commit()

def classify_alert(alert):
    """Classify alert severity based on its content (simple keyword-based logic)."""
    content = alert.get("content", "").lower()
    # Keywords for high severity
    high_keywords = ["malware", "ransomware", "critical"]
    # Keywords for medium severity
    medium_keywords = ["error", "failed", "phishing", "scan", "scanning"]
    # Determine severity
    for kw in high_keywords:
        if kw in content:
            return "High"
    for kw in medium_keywords:
        if kw in content:
            return "Medium"
    return "Low"

def route_alert(alert):
    """Route the alert based on its classified severity, enforcing governance policies."""
    aid = alert["id"]
    sev = alert["severity"]
    if sev == "High":
        # High severity: attempt escalation with governance check
        if not agent_token_present:
            # No valid token -> cannot escalate
            log_decision(aid, "escalation", {
                "decision": "denied",
                "reason": "no_token",
                "required_clearance": REQUIRED_CLEARANCE
            })
            # Keep alert for manual handling
            alert["status"] = "unresolved"
            live_alerts[aid] = {"severity": sev, "status": alert["status"]}
        elif agent_clearance_level < REQUIRED_CLEARANCE:
            # Clearance too low -> deny escalation
            log_decision(aid, "escalation", {
                "decision": "denied",
                "reason": "insufficient_clearance",
                "required_clearance": REQUIRED_CLEARANCE,
                "actual_clearance": agent_clearance_level
            })
            alert["status"] = "unresolved"
            live_alerts[aid] = {"severity": sev, "status": alert["status"]}
        else:
            # Escalation approved -> perform action
            log_decision(aid, "escalation", {
                "decision": "approved",
                "target": "Incident Response"
            })
            alert["status"] = "escalated"
            # We assume the incident response team takes over, so remove from live alerts
            if aid in live_alerts:
                live_alerts.pop(aid)
    elif sev == "Medium":
        # Medium severity: route to Tier-2 support queue
        log_decision(aid, "routing", {
            "destination": "Tier-2 Support"
        })
        alert["status"] = "unresolved"
        live_alerts[aid] = {"severity": sev, "status": alert["status"]}
    else:
        # Low severity: auto-resolve
        log_decision(aid, "auto_resolution", {
            "decision": "closed"
        })
        alert["status"] = "resolved"
        # No need to keep in live_alerts as it's resolved
        if aid in live_alerts:
            live_alerts.pop(aid)

def process_alert(alert):
    """Process a single alert through classification and routing."""
    # Classify
    severity = classify_alert(alert)
    alert["severity"] = severity
    log_decision(alert["id"], "classification", {"severity": severity})
    # Route according to severity (includes governance checks on escalation)
    route_alert(alert)
    return alert  # returning alert with updated status/severity (not used further here)

# --- Simulation of streaming alerts ---
alerts = [
    {"id": 1, "source": "Firewall",    "content": "Blocked IP scanning multiple ports"},  # likely Medium
    {"id": 2, "source": "Endpoint",    "content": "Malware detected on host X"},           # High (malware keyword)
    {"id": 3, "source": "EmailGateway","content": "Phishing email reported by user"},      # Medium (phishing keyword)
    {"id": 4, "source": "SIEM",        "content": "Multiple failed login attempts detected"},  # Medium (failed keyword)
    {"id": 5, "source": "EDR",         "content": "Ransomware behavior observed on device Y"}  # High (ransomware keyword)
]

print("Starting alert stream processing...")
for alert in alerts:
    # Simulate a change in clearance: before alert 5, promote agent to clearance 5
    if alert["id"] == 5:
        agent_clearance_level = 5
        print("Agent clearance elevated to 5 for alert 5")
    process_alert(alert)
    print(f"Processed alert {alert['id']}: severity {alert['severity']}, status {alert.get('status')}.")

# --- Simulation of batch job (cleanup) ---
def batch_cleanup():
    # Remove resolved or escalated alerts from live_alerts cache
    removed = []
    for aid, info in list(live_alerts.items()):
        if info.get("status") in ("resolved", "escalated"):
            removed.append(aid)
            live_alerts.pop(aid, None)
    # Log the batch cleanup action
    log_decision("batch", "cleanup", {"removed_alerts": removed})
    return removed

print("\nPerforming batch cleanup of resolved alerts...")
# Simulate that alert 3 got resolved by Tier-2 (for demo purposes)
if 3 in live_alerts:
    live_alerts[3]["status"] = "resolved"
removed_ids = batch_cleanup()
print(f"Cleanup removed alerts: {removed_ids}\n")

print("Final live_alerts cache:", live_alerts)
print("Decision log entries:", len(decision_logs))
