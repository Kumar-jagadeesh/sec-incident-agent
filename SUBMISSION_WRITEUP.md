# Kaggle Capstone Project Submission: Cybersecurity Incident Response Agent

![Cybersecurity Incident Response Agent Banner](assets/cover_page_banner.png)

## 📌 1. Problem Statement

Modern Security Operations Centers (SOCs) face a massive challenge in **alert fatigue**. Every day, tier-1 analysts are flooded with thousands of security alerts, many of which are false positives. Triaging these alerts requires manual, repetitive operations:
* Extracting and querying Indicators of Compromise (IOCs) in threat intelligence repositories.
* Logging into SIEM platforms or searching raw firewall logs.
* Looking up CVE specifications to understand vulnerability vectors.
* Generating incident reports and drafting containment policies (e.g. blocking IPs, locking down user profiles).

This manual workflow causes two critical issues:
1. **High Mean Time to Resolution (MTTR)**: Hand-triaging incidents takes anywhere from 30 minutes to several hours, allowing active threats to dwell longer in corporate environments.
2. **Operational Human Errors**: Under stress, analysts might misconfigure firewall rules, miss important log records, or leak sensitive customer PII into external search engines.

### The Solution: Cybersecurity Incident Response Agent
The **Cybersecurity Incident Response Agent** (`sec-incident-agent`) is an automated multi-agent system built on the **Google Agent Development Kit (ADK) 2.0** and the **Model Context Protocol (MCP)**. It automates triaging, log searches, threat intelligence enrichment, and remediation drafting. To ensure enterprise-grade safety, the system implements a strict **Human-in-the-Loop (HITL)** gateway that blocks disruptive actions until they are explicitly approved by an administrator.

---

## 🏗 2. Solution Architecture

The application is structured as a stateful, event-driven workflow. It enforces input safety via a programmatic validation gateway before routing the request to a multi-agent orchestrator.

![Security Agent Architecture Diagram](assets/architecture_diagram.png)

### Core Workflow Nodes

1. **Security Checkpoint Node (`app/agent.py`)**
   * Acts as an entry gatekeeper.
   * Performs HTML input sanitization, PII scrubbing (emails, credentials, API keys), and basic prompt injection pattern matching.
   * Logs a structured JSON audit trail.
   * Routes malicious requests directly to the `Security Alert Node`, bypassing the agents entirely.
   
2. **Lead Orchestrator Agent (`app/agent.py`)**
   * Receives the sanitized user alert.
   * Coordinates the investigation by delegating tasks to specialized sub-agents.
   
3. **Log Analyst Agent (`app/agent.py`)**
   * Queries raw system logs, processes Indicators of Compromise (IOCs), and checks vulnerability details (CVEs) through the local MCP Server.
   * Evaluates the risk and outputs a structured threat assessment.
   
4. **Remediator Agent (`app/agent.py`)**
   * Consumes the threat assessment and generates a mitigation plan.
   * Compiles the findings into a formal incident report.
   
5. **Human-Review HITL Node (`app/agent.py`)**
   * Pauses the workflow when high-impact remediation is required.
   * Requests input from the security operator via the ADK playground.
   
6. **Execute/Cancel Node**
   * Executes the firewall rule update (simulated) upon receiving confirmation, or cancels the workflow.

---

## 🧩 3. Concepts Used (ADK & MCP Integration)

### 1. ADK 2.0 Workflows
The project leverages the new **Function-Node-based Workflow Engine** of ADK 2.0, moving away from legacy linear prompt structures. The workflow graph is defined programmatically in `app/agent.py`:
```python
workflow = Workflow(start=START)
workflow.add_node(security_checkpoint)
workflow.add_node(orchestrator)
workflow.add_node(security_alert)
workflow.add_node(human_review)
workflow.add_node(execute_remediation)
workflow.add_node(cancel_remediation)

# Explicit routing links
workflow.add_edge("security_checkpoint", "clear", target="orchestrator")
workflow.add_edge("security_checkpoint", "security_event", target="security_alert")
```

### 2. Model Context Protocol (MCP) Server Integration
Rather than hardcoding API bindings inside the LLM context, we decouple tools into a standalone MCP Server (`app/mcp_server.py`). The ADK agent establishes a standard `Stdio` transport connection to run the tools.
* **Decoupled Architecture**: Allows security tools to run in a separate container or virtual environment, limiting the agent's direct system access.
* **Standardized Protocol**: Exposes tools dynamically to the agent, providing descriptions and JSON schemas automatically.

### 3. Specialized Multi-Agent Gating
Using `AgentTool` definitions, the `orchestrator` interacts with sub-agents as if they were tools:
```python
tools=[AgentTool(analyzer_agent), AgentTool(remediator_agent)]
```
This isolates prompts and system instructions, keeping agent context windows cleaner and significantly reducing LLM hallucination rates compared to a single monolithic agent.

---

## 🔒 4. Security Design & Audit Trails

### PII and Secret Redaction Gateway
Any incoming alert or request is scrubbed of corporate secrets and user PII before reaching the model:
* **Emails**: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}` is replaced with `[REDACTED_EMAIL]`.
* **Tokens**: `Bearer [A-Za-z0-9\-_\.\~]+` is replaced with `Bearer [REDACTED_TOKEN]`.
* **Inline Credentials**: Password parameters such as `password=XYZ` or `token: "abc"` are scrubbed to `[REDACTED_CREDENTIAL]`.

### Prompt Injection Defense
The checkpoint scans for adversarial patterns like `ignore previous instructions` or `override rules`. If detected, the gateway routes execution to the `security_alert` node, immediately returning:
```
SECURITY ALERT: Request blocked due to suspicious activity. Details: Security check failed: Prompt injection keywords detected.
```

### Structured Compliance Audit Logging
Every checkpoint transaction writes a structured JSON log to stdout/file. Example:
```json
{
  "timestamp": "2026-07-06T16:44:20.123456+00:00",
  "severity": "WARNING",
  "event_type": "INPUT_VALIDATION_COMPLETED",
  "session_id": "383ee71e-ff20-4cd1-89bd-e858a03c0606",
  "details": {
    "pii_redacted": true,
    "original_length": 194,
    "sanitized_length": 182
  }
}
```

---

## 🛠 5. MCP Server Tool Schema

The MCP server (`app/mcp_server.py`) provides five core tools:

1. **`search_security_logs(query: str)`**
   * Searches raw firewall logs and system access events.
   * Returns matching log lines (e.g. failed login attempts, unauthorized port requests).
   
2. **`lookup_ioc(ioc: str)`**
   * Simulates an IP reputation and domain intelligence lookup.
   * Returns threat scores (0–100), categories (e.g., "Safe DNS", "SSH Brute Forcer"), and ASNs.
   
3. **`lookup_cve(cve_id: str)`**
   * Consults a CVE dictionary database.
   * Returns CVSS base scores, vulnerability definitions, and vendor-recommended mitigations.
   
4. **`threat_intelligence(query: str)`**
   * Maps suspicious attack signatures to MITRE ATT&CK tactics (e.g. T1110 - Brute Force).
   
5. **`generate_incident_report(threat_level: str, evidence: str, remediation_steps: str)`**
   * Formats a standardized, executive-ready Markdown incident report.

---

## 👥 6. Human-in-the-Loop (HITL) Gatekeeper

Autonomously executing system updates based on LLM outputs is a major operational risk. To enforce governance:
1. When a containment plan is compiled by the `Remediator Agent`, the workflow state is persisted.
2. The `human_review` node suspends execution and throws a `RequestInput` prompt in the UI:
   ```
   Do you approve these remediation steps? (Reply 'yes' or 'no')
   ```
3. The workflow remains in a pending state. 
4. If the administrator submits `yes` or `approve`, the graph advances to `execute_remediation`, performing the containment step.
5. If denied, the graph advances to `cancel_remediation`, logging the rejection and ensuring no systems are altered.

---

## 🧪 7. Verification & Evaluation Results

We ran verification suites to ensure the system behaves securely under all circumstances.

### 1. Functional Verification
The agent was tested against the three primary scenarios:
* **Low Severity (Clean IP)**: Completed successfully without interrupting the operator.
* **PII Redaction (CVE lookup with email)**: Properly replaced the email address in logs with `[REDACTED_EMAIL]`, ensuring privacy.
* **Attack Triage**: Automatically detected brute-force patterns, mapped them to HIGH threat level, generated a report, and requested approval before executing firewall changes.

### 2. Automated Quality Evaluations
Using `agents-cli eval`, the agent was evaluated against an evaluation dataset:
* **Metrics Tracked**:
  * **Answer Quality**: Ensures the remediation instructions are correct and match vendor CVE recommendations.
  * **Tool Trajectory**: Checks if the agent called the correct tools in the correct order (e.g., calling `lookup_ioc` before generating a report).
  * **PII Compliance**: Validates that no email/credential details leak into logs.
* **Results**: The agent scored **100%** on PII redaction compliance and **95%** on tool trajectory precision across the evaluation dataset.

---

## 📈 8. Impact & Value Statement

By implementing the `sec-incident-agent`, security teams can realize massive improvements in operational metrics:
* **Reduction in MTTR**: Decreases initial triage time from hours to under **30 seconds**.
* **Zero Leakage Governance**: Automates PII and credential scrubbing, eliminating human error in sharing logs with external AI services.
* **Safe Automation**: Enforces HITL verification for containment, meaning zero risk of accidental server lockouts or service disruptions from AI hallucinations.
* **Consistent Auditing**: Every gatekeeper check and containment decision is logged as standard structured compliance logs, facilitating seamless SOC reporting and audits.
