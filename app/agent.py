import os
import sys
import re
import json
import datetime
from google.adk.agents import LlmAgent
from google.adk.models import Gemini
from google.adk.tools import AgentTool
from google.adk.apps import App, ResumabilityConfig
from google.adk.workflow import Workflow, START
from google.adk.events.event import Event
from google.adk.events.request_input import RequestInput
from google.adk.agents.context import Context
from google.genai import types

from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

from app.config import config

# Define Model
model = Gemini(model=config.model)

# Set up MCP Connection
python_exe = sys.executable
mcp_server_path = os.path.join(os.path.dirname(__file__), "mcp_server.py")

mcp_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=python_exe,
            args=[mcp_server_path],
        ),
    ),
)

# 1. Specialized Analyst Agent
analyzer_agent = LlmAgent(
    name="analyzer_agent",
    model=model,
    instruction=(
        "You are a Cybersecurity Log Analyst agent.\n"
        "Analyze the provided system/firewall/application logs or event description to detect signs of compromise, attack signatures, or anomalies.\n"
        "You have access to security logs and threat intelligence databases via MCP tools:\n"
        "- `search_security_logs`: Search logs for malicious activity/IPs/signatures.\n"
        "- `lookup_ioc`: Retrieve reputation details and threat scores for IPs, domains, or file hashes.\n"
        "- `lookup_cve`: Check CVSS scores and description of active vulnerabilities.\n"
        "- `threat_intelligence`: Map techniques to MITRE ATT&CK tactics and risk levels.\n\n"
        "Examine timestamps, source IPs, action types, and request details. Always use your tools to cross-reference and verify findings.\n"
        "Return a structured summary of the threat level (LOW, MEDIUM, HIGH, CRITICAL), active techniques, and specific evidence."
    ),
    description="Analyzes logs and event data to detect cybersecurity threats and compromise.",
    tools=[mcp_toolset]
)

# 2. Specialized Remediator Agent
remediator_agent = LlmAgent(
    name="remediator_agent",
    model=model,
    instruction=(
        "You are a Security Remediation and Containment agent.\n"
        "Given an incident summary and threat analysis, formulate a precise list of containment and remediation actions.\n"
        "You have access to incident reporting tools via MCP tools:\n"
        "- `generate_incident_report`: Create a structured Markdown incident report with threat level and evidence.\n\n"
        "Define firewall rule blocks, account lockouts, software patching, or service restarts.\n"
        "Always call `generate_incident_report` to generate the final incident report. Return the generated report."
    ),
    description="Formulates containment and remediation plans and generates security reports.",
    tools=[mcp_toolset]
)

# 3. Lead Orchestrator Agent
orchestrator = LlmAgent(
    name="orchestrator",
    model=model,
    instruction=(
        "You are the Lead Cybersecurity Incident Response Orchestrator.\n"
        "Your job is to coordinate the response to potential security incidents.\n"
        "To do this, you have access to two specialized sub-agents:\n"
        "- `analyzer_agent`: Call this to analyze logs/events and detect threats.\n"
        "- `remediator_agent`: Call this to build a remediation/containment plan once a threat is identified.\n\n"
        "First, delegate the log/event analysis to `analyzer_agent`.\n"
        "Then, if a threat is found, delegate to `remediator_agent` to draft containment actions.\n"
        "Compile the results into a final incident report with threat level, evidence, and remediation steps."
    ),
    tools=[AgentTool(analyzer_agent), AgentTool(remediator_agent)]
)

# Audit logger helper
def log_audit(severity: str, event_type: str, session_id: str, details: dict):
    log_entry = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "severity": severity,
        "event_type": event_type,
        "session_id": session_id,
        "details": details
    }
    print(f"AUDIT_LOG: {json.dumps(log_entry)}")

# 4. Security Checkpoint Function Node
def security_checkpoint(ctx: Context, node_input: types.Content) -> Event:
    user_input = ""
    if node_input and node_input.parts:
        user_input = node_input.parts[0].text or ""
    
    # A. Prompt Injection Detection (common attack patterns)
    lower_input = user_input.lower()
    injection_patterns = [
        "ignore previous instructions",
        "system prompt",
        "override rules",
        "bypass restrictions",
        "you are now a",
        "jailbreak",
        "dan mode",
        "do anything now"
    ]
    
    detected_keywords = [pat for pat in injection_patterns if pat in lower_input]
    if detected_keywords:
        log_audit(
            severity="CRITICAL",
            event_type="PROMPT_INJECTION_DETECTED",
            session_id=ctx.session.id,
            details={"detected_keywords": detected_keywords, "raw_input": user_input[:200]}
        )
        return Event(
            output={"error": f"Security check failed: Prompt injection keywords detected: {detected_keywords}"},
            route="security_event",
            state={"incident_type": "Prompt Injection Attempt"}
        )
        
    # B. OWASP-inspired Validation & Input Sanitization
    # Strip HTML script and execution tags to prevent XSS-like payloads
    sanitized_input = re.sub(r'<script.*?>.*?</script>', '[STRIPPED_SCRIPT]', user_input, flags=re.IGNORECASE)
    sanitized_input = re.sub(r'<[^>]*>', '', sanitized_input)  # Strip general HTML tags
    
    # C. PII Redaction
    scrubbed_input = sanitized_input
    
    # 1. Redact Emails
    scrubbed_input = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        '[REDACTED_EMAIL]',
        scrubbed_input
    )
    
    # 2. Redact passwords/secrets/tokens in inline parameters (e.g. password=XYZ or token: "abc")
    scrubbed_input = re.sub(
        r'\b(password|pass|passwd|secret|token|apikey|api_key)\s*[:=]\s*["\']?[A-Za-z0-9_\-\.\~]{8,}["\']?\b',
        r'\1=[REDACTED_CREDENTIAL]',
        scrubbed_input,
        flags=re.IGNORECASE
    )
    
    # 3. Redact Authorization Headers
    scrubbed_input = re.sub(
        r'\bBearer\s+[A-Za-z0-9\-_\.\~]+\b',
        'Bearer [REDACTED_TOKEN]',
        scrubbed_input,
        flags=re.IGNORECASE
    )
    
    # Note on IP addresses: We do NOT redact IP addresses globally because they are
    # required for log queries and IOC reputation checks.
    
    # D. Structured JSON Audit Logging
    scrubbed_differs = (scrubbed_input != user_input)
    log_audit(
        severity="WARNING" if scrubbed_differs else "INFO",
        event_type="INPUT_VALIDATION_COMPLETED",
        session_id=ctx.session.id,
        details={
            "pii_redacted": scrubbed_differs,
            "original_length": len(user_input),
            "sanitized_length": len(scrubbed_input)
        }
    )
    
    return Event(
        output=scrubbed_input,
        route="clear",
        state={"scrubbed_input": scrubbed_input}
    )

# 5. Security Alert Node
def security_alert(ctx: Context, node_input: dict) -> Event:
    msg = f"SECURITY ALERT: Request blocked due to suspicious activity. Details: {node_input.get('error')}"
    return Event(
        output=msg,
        content=types.Content(
            role="model",
            parts=[types.Part.from_text(text=msg)]
        )
    )

# 6. Human Review HITL Node
async def human_review(ctx: Context, node_input: types.Content | str):
    if isinstance(node_input, str):
        text = node_input
    else:
        text = node_input.parts[0].text if (node_input and node_input.parts) else ""
    ctx.state["proposed_remediation"] = text
    
    # Check if this requires critical review
    # In cybersecurity, we perform human review for incident remediations with MEDIUM, HIGH, or CRITICAL severity
    lower_text = text.lower()
    requires_review = False
    if "threat level" in lower_text:
        for level in ["medium", "high", "critical"]:
            if level in lower_text:
                requires_review = True
                break

    if not requires_review:
        content_val = node_input if not isinstance(node_input, str) else types.Content(
            role="model",
            parts=[types.Part.from_text(text=text)]
        )
        yield Event(
            output=text,
            content=content_val
        )
        return

    if ctx.resume_inputs and "approve_action" in ctx.resume_inputs:
        user_choice = ctx.resume_inputs["approve_action"]
        
        log_audit(
            severity="INFO",
            event_type="HITL_DECISION_RECEIVED",
            session_id=ctx.session.id,
            details={"decision": user_choice}
        )
        
        if user_choice.lower() in ["yes", "approve", "y"]:
            yield Event(
                output="Remediation approved by human.",
                route="approved",
                state={"human_decision": "approved"}
            )
        else:
            yield Event(
                output="Remediation denied by human.",
                route="denied",
                state={"human_decision": "denied"}
            )
        return
            
    log_audit(
        severity="WARNING",
        event_type="HITL_PAUSE_REQUESTED",
        session_id=ctx.session.id,
        details={"proposed_remediation": text[:200]}
    )
    
    yield RequestInput(
        interrupt_id="approve_action",
        message=f"Orchestrator proposed remediation:\n{text}\n\nDo you approve these remediation steps? (Reply 'yes' or 'no')"
    )


# 7. Execution Nodes
def execute_remediation(ctx: Context, node_input: str) -> Event:
    msg = f"Remediation executed successfully: {node_input}"
    log_audit(
        severity="INFO",
        event_type="REMEDIATION_EXECUTED",
        session_id=ctx.session.id,
        details={"status": "success"}
    )
    return Event(
        output=msg,
        content=types.Content(
            role="model",
            parts=[types.Part.from_text(text=msg)]
        )
    )

def cancel_remediation(ctx: Context, node_input: str) -> Event:
    msg = f"Remediation canceled by human. Incident remains open for manual investigation."
    log_audit(
        severity="WARNING",
        event_type="REMEDIATION_CANCELED",
        session_id=ctx.session.id,
        details={"status": "canceled"}
    )
    return Event(
        output=msg,
        content=types.Content(
            role="model",
            parts=[types.Part.from_text(text=msg)]
        )
    )

# Define Workflow Graph
workflow = Workflow(
    name="workflow",
    edges=[
        (START, security_checkpoint),
        (security_checkpoint, {"clear": orchestrator, "security_event": security_alert}),
        (orchestrator, human_review),
        (human_review, {"approved": execute_remediation, "denied": cancel_remediation})
    ]
)

# App instance
app = App(
    name="app",
    root_agent=workflow,
    resumability_config=ResumabilityConfig(is_resumable=True)
)

root_agent = workflow

