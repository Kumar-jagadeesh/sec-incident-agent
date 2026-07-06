import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Cybersecurity Incident Response Server")

# 1. IOC Lookup Tool
@mcp.tool()
def lookup_ioc(ioc: str, ioc_type: str) -> str:
    """Look up an Indicator of Compromise (IOC) like an IP address, domain, or file hash.
    
    Args:
        ioc: The IOC value (e.g., '198.51.100.42', 'evil-malware-cnc.biz', '85ade9...').
        ioc_type: Type of IOC: 'ip', 'domain', or 'hash'.
    """
    ioc_type_clean = ioc_type.lower().strip()
    
    # Pre-coded threat data for demo/test purposes
    mock_db = {
        "ip": {
            "198.51.100.42": {"threat_score": 95, "status": "Malicious", "category": "Botnet CnC", "asn": "AS45678", "country": "RU"},
            "203.0.113.15": {"threat_score": 82, "status": "Suspicious", "category": "SSH Brute Forcer", "asn": "AS12345", "country": "CN"},
            "8.8.8.8": {"threat_score": 0, "status": "Clean", "category": "Safe DNS", "asn": "AS15169", "country": "US"}
        },
        "domain": {
            "evil-malware-cnc.biz": {"threat_score": 100, "status": "Malicious", "category": "Dynamic DNS / Malware Hosting", "registrar": "NameCheap"},
            "google.com": {"threat_score": 0, "status": "Clean", "category": "Search Engine", "registrar": "MarkMonitor"}
        },
        "hash": {
            "85ade910b5f5cc1112443a6d4d12e879f8bfca1965e6d6d7a4eb3cf7d11019ab": {"threat_score": 98, "status": "Malicious", "malware_family": "WannaCry Ransomware", "type": "PE32 Executable"}
        }
    }
    
    db = mock_db.get(ioc_type_clean, {})
    res = db.get(ioc, None)
    
    if res:
        return json.dumps({"ioc": ioc, "type": ioc_type_clean, "found": True, "details": res}, indent=2)
    else:
        # Default fallback for query
        return json.dumps({
            "ioc": ioc,
            "type": ioc_type_clean,
            "found": False,
            "details": {
                "threat_score": 45,
                "status": "Unknown",
                "category": "No threat history found in reputation database.",
                "reputation": "Neutral"
            }
        }, indent=2)

# 2. CVE Lookup Tool
@mcp.tool()
def lookup_cve(cve_id: str) -> str:
    """Retrieve vulnerability details and remediation steps for a specific CVE ID.
    
    Args:
        cve_id: The CVE ID (e.g., 'CVE-2021-44228', 'CVE-2024-3094').
    """
    cve_id_clean = cve_id.upper().strip()
    
    mock_cves = {
        "CVE-2021-44228": {
            "title": "Log4Shell Apache Log4j RCE",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints, leading to remote code execution.",
            "mitigation": "Upgrade to Log4j v2.17.1 or set log4j2.formatMsgNoLookups=true."
        },
        "CVE-2024-3094": {
            "title": "XZ Utils Backdoor",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Malicious code was discovered in the upstream tarballs of xz-utils, starting with version 5.6.0, allowing unauthorized SSH access.",
            "mitigation": "Downgrade xz-utils to version 5.4.x immediately."
        }
    }
    
    res = mock_cves.get(cve_id_clean, None)
    if res:
        return json.dumps({"cve_id": cve_id_clean, "found": True, "details": res}, indent=2)
    else:
        return json.dumps({
            "cve_id": cve_id_clean,
            "found": False,
            "details": {
                "title": f"Unknown Vulnerability ({cve_id_clean})",
                "cvss_score": 5.0,
                "severity": "MEDIUM",
                "description": "No local intelligence on this CVE. Please consult MITRE CVE Database.",
                "mitigation": "Apply vendor-supplied patches and audit system dependency versions."
            }
        }, indent=2)

# 3. Threat Intelligence Tool
@mcp.tool()
def threat_intelligence(attack_technique: str) -> str:
    """Map a threat or behavior to MITRE ATT&CK tactics, mitigation plans, and risk level.
    
    Args:
        attack_technique: The technique name or ID (e.g., 'T1110', 'Brute Force', 'SQL Injection').
    """
    tech_clean = attack_technique.lower().strip()
    
    mock_techniques = {
        "t1110": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "risk_level": "MEDIUM",
            "mitigation": "Enforce account lockouts, use Multi-Factor Authentication (MFA), and monitor login failures."
        },
        "brute force": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "risk_level": "MEDIUM",
            "mitigation": "Enforce account lockouts, use Multi-Factor Authentication (MFA), and monitor login failures."
        },
        "sql injection": {
            "name": "SQL Injection",
            "tactic": "Initial Access / Privilege Escalation",
            "risk_level": "HIGH",
            "mitigation": "Use parameterized queries, validate and sanitize all inputs, and restrict DB user privileges."
        }
    }
    
    res = mock_techniques.get(tech_clean, None)
    if res:
        return json.dumps({"query": attack_technique, "found": True, "details": res}, indent=2)
    else:
        return json.dumps({
            "query": attack_technique,
            "found": False,
            "details": {
                "name": attack_technique,
                "tactic": "Generic Defense Evasion",
                "risk_level": "LOW",
                "mitigation": "Review application logs, update signatures on Web Application Firewall (WAF), and audit logs."
            }
        }, indent=2)

# 4. Log Search Tool
@mcp.tool()
def search_security_logs(query: str, limit: int = 10) -> str:
    """Query security, access, and firewall logs for compromise indicators.
    
    Args:
        query: Search term (e.g., '198.51.100.42', 'failed login', 'sql injection').
        limit: Max number of log records to return.
    """
    query_clean = query.lower().strip()
    
    mock_logs = [
        {"timestamp": "2026-07-06T12:01:05Z", "source": "198.51.100.42", "destination": "prod-web-01", "port": 443, "action": "ALLOW", "message": "SSL connection established"},
        {"timestamp": "2026-07-06T12:01:10Z", "source": "198.51.100.42", "destination": "prod-web-01", "port": 80, "action": "ALLOW", "message": "GET /login?user=admin' OR '1'='1' -- HTTP/1.1 (Possible SQL Injection)"},
        {"timestamp": "2026-07-06T12:02:15Z", "source": "203.0.113.15", "destination": "ssh-gateway", "port": 22, "action": "DENY", "message": "Failed login attempt for user 'root'"},
        {"timestamp": "2026-07-06T12:02:18Z", "source": "203.0.113.15", "destination": "ssh-gateway", "port": 22, "action": "DENY", "message": "Failed login attempt for user 'admin'"},
        {"timestamp": "2026-07-06T12:02:22Z", "source": "203.0.113.15", "destination": "ssh-gateway", "port": 22, "action": "DENY", "message": "Failed login attempt for user 'ubuntu'"},
        {"timestamp": "2026-07-06T12:05:00Z", "source": "192.168.1.50", "destination": "app-server", "port": 8080, "action": "ALLOW", "message": "User alice@example.com logged in successfully"}
    ]
    
    matches = []
    for log in mock_logs:
        log_str = json.dumps(log)
        if query_clean in log_str.lower():
            matches.append(log)
            if len(matches) >= limit:
                break
                
    return json.dumps({"query": query, "total_matches": len(matches), "logs": matches}, indent=2)

# 5. Incident Report Generator
@mcp.tool()
def generate_incident_report(incident_id: str, summary: str, threat_level: str, evidence: str) -> str:
    """Generate a clean, structured Markdown security incident report.
    
    Args:
        incident_id: Unique identifier for the incident (e.g. INC-2026-001).
        summary: Executive summary of the threat.
        threat_level: Severity rating (LOW, MEDIUM, HIGH, CRITICAL).
        evidence: Relevant log snippets or IOC details.
    """
    report = f"""# SECURITY INCIDENT REPORT: {incident_id.upper()}
**Threat Level:** {threat_level.upper()}
**Report Generated:** 2026-07-06

## Executive Summary
{summary}

## Evidence / Logs
```json
{evidence}
```

## Recommended Actions
1. Block any associated malicious IP addresses at the perimeter firewall.
2. Quarantine affected host systems to prevent lateral movement.
3. Terminate active sessions and force credential rotation for implicated users.
4. File formal compliance / data privacy breach notification if PII exposure is verified.
"""
    return report

if __name__ == "__main__":
    mcp.run("stdio")
