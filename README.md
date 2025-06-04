# Security-Alert-Triage-Agent
🚨 Cybersecurity Alert Triage Agent | Intelligent, policy-driven Python simulation that autonomously classifies, routes, and escalates security alerts based on severity, identity-based governance, and data storage tradeoffs (SQL &amp; NoSQL).
## 1. System Use Case and Rationale
The system simulates an intelligent agent designed to automate cybersecurity alert triage. It classifies alerts based on severity, autonomously routing or escalating them based on governance policies. The rationale for this agent is to ensure timely processing of critical threats, reduce alert fatigue, and enforce strict compliance with organizational policies.

## 2. Governance Rules Used
- **Identity-Based Access Control (IBAC):** Actions are permitted based on the clearance level associated with the agent's token.
- **Clearance Requirements:**
  - High-severity alert escalation requires clearance level ≥ 5.
  - Alerts with insufficient clearance or missing tokens are denied escalation and flagged for manual review.
- **Logging and Observability:** All actions, approvals, denials, and routing decisions are logged explicitly for traceability.

## 3. Architectural Tradeoffs and Constraints
- **SQL (SQLite):** Chosen for consistent, durable logging of decisions, reflecting a CP (Consistency and Partition-tolerance) system under CAP theorem considerations.
- **NoSQL (In-memory Cache):** Simulated using Python dictionaries for fast, real-time alert handling, aligning with AP (Availability and Partition-tolerance) characteristics.
- **Stream vs. Batch:** Real-time stream handling for immediate alert processing, supplemented with batch processing for periodic maintenance tasks.

These tradeoffs allow the agent to balance speed, scalability, and reliability effectively.
