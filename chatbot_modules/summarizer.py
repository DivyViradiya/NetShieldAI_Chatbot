import json
from typing import Dict, Any, List, Callable
import os
import sys
import dotenv
import uuid
import re
import logging

# Initialize module logger
logger = logging.getLogger(__name__)

# Load environment variables from a .env file (if present)
dotenv.load_dotenv()

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from chatbot_modules import config 

def _format_nmap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze parsed NetShieldAI (Nmap) data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Concrete attacker scenarios, priority ordering, exposure context,
        scan coverage disclaimer, and owner-tagged remediation steps
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Data from JSON Structure ---
    metadata  = parsed_data.get("scan_metadata", {})
    summary   = parsed_data.get("summary", {})
    ports     = parsed_data.get("open_ports", [])

    target_ip        = metadata.get("target_ip", "N/A")
    scan_args        = metadata.get("scan_arguments") or ""
    scan_date        = metadata.get("scan_date", "N/A")
    security_posture = metadata.get("security_posture", "Unknown")

    ports_found_count = summary.get("ports_found", 0)
    threats_detected  = summary.get("threats_detected", 0)

    # --- Calculate unique services for the Service Inventory Summary ---
    unique_services_list = list(set([p.get("service_name", "Unknown") for p in ports if p.get("service_name")]))
    services_list_str = ", ".join(unique_services_list) if unique_services_list else "None"

    # --- 2. Determine Scan Type, Coverage & Limitations ---
    args_lower = scan_args.lower()
    if "-a" in args_lower:
        scan_type        = "Aggressive Scan (-A) — OS Detection, Version Detection & Script Scanning"
        scan_coverage    = "OS fingerprinting, service versions, and common vulnerability scripts"
        scan_limitations = (
            "did NOT test login credentials, internal network traffic, "
            "application-layer security, or devices other than the target node"
        )
    elif "-sv" in args_lower:
        scan_type        = "Service Version Detection (-sV)"
        scan_coverage    = "Open ports and running service versions on the target node"
        scan_limitations = (
            "did NOT perform vulnerability testing, OS fingerprinting, "
            "credential checks, or scan any other devices on the network"
        )
    elif "--script vuln" in args_lower:
        scan_type        = "Vulnerability Scan (--script vuln)"
        scan_coverage    = "Open ports and known vulnerability signatures on exposed services"
        scan_limitations = (
            "did NOT test authentication strength, internal traffic, "
            "application logic flaws, or devices other than the target node"
        )
    elif "-ss" in args_lower:
        scan_type        = "TCP SYN Stealth Scan (-sS)"
        scan_coverage    = "Open TCP ports on the target node"
        scan_limitations = (
            "did NOT detect service versions, run vulnerability scripts, "
            "check credentials, or scan UDP ports or other network devices"
        )
    else:
        scan_type        = "Standard TCP / Port Scan"
        scan_coverage    = "Open TCP ports on the target node"
        scan_limitations = (
            "did NOT detect service versions, test for vulnerabilities, "
            "check credentials, or scan other devices on the network"
        )

    # --- 3. Build Ports Block ---
    if ports:
        ports_block_lines = ["### Open Ports Detail:"]
        for p in ports:
            version_info    = p.get("service_version", "N/A")
            display_version = (
                "Same as Service Name"
                if version_info == p.get("service_name")
                else version_info
            )
            ports_block_lines.append(
                f"- Port {p.get('port')}/{p.get('protocol')} ({p.get('state')}): "
                f"Service='{p.get('service_name')}', "
                f"Version='{display_version}', "
                f"Process='{p.get('local_process')}', "
                f"AI Threat Magnitude='{p.get('tctr_magnitude_percent', 'N/A')}%', "
                f"Intelligence='{p.get('intelligence_breakdown', 'N/A')}'"
            )
        ports_block = "\n".join(ports_block_lines)
    else:
        ports_block = "No open ports were detected during this scan."

    # --- 4. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior Network Security Consultant** — an expert at making \
complex cybersecurity findings clear and actionable for everyday users, not just \
technical professionals.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the Nmap scan data provided in the [SCAN DATA] block below and produce a \
professional "Network Assessment Briefing" report in exactly 6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "Port 22 (SSH — the digital 'front door' used for remote login)"
- Treat the reader as an intelligent non-expert: someone who owns or manages a \
network but is NOT a cybersecurity professional.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [SCAN DATA] block. Do not invent or assume \
any additional findings.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  Every risk label in the table (Section 2) MUST follow this exact format:
    <Level> — <One-sentence plain-English reason>
    Example: "High — This port is unencrypted and commonly targeted by attackers."
5.  Every Priority label in the table (Section 2) MUST use exactly one of:
    Critical — Fix Now / High — Fix Soon / Medium — Monitor / Low — No Action Needed
6.  If Threats Detected > 0, those findings MUST be the first items covered in \
Section 3 (Deep Dive Analysis).
7.  Remediation advice (Section 4) must be written as actionable steps a \
non-technical user can realistically follow — avoid commands or code snippets.
8.  Every remediation bullet (Section 4) MUST end with an owner tag on a new line:
    **Owner: Self** | **Owner: ISP** | **Owner: IT Support**
    Choose the most realistic owner for a non-technical user.
9.  Remediation bullets (Section 4) MUST be ordered by priority: \
highest-risk issue first, lowest-risk last.
10. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 decision paths: Critical / At Risk / Secure.
    b. Highlight only the path that matches the Security Posture from [SCAN DATA].
    c. Each path must have a "Your Situation" marker — either [ YOU ARE HERE ] \
or nothing, based on the actual posture verdict.
11. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
12. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary

Before the verdict paragraph, produce a Markdown metadata table with \
exactly these columns:
| Field | Value |
|---|---|
| Report Generated By | NetShieldAI Automated Security Analysis |
| Scan Target | {target_ip} |
| Scan Date | {scan_date} |
| Services Detected | {ports_found_count} running {services_list_str} |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures \
the reader can immediately verify which system was assessed and when.

Network Exposure Window: Include a one-sentence statement on what the \
current open port configuration means for the target's exposure to the \
public internet.

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is — \
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of \
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and \
            who should take it.

This paragraph must be written as if explaining to a business owner \
who has no technical background and five minutes to decide whether \
to act. Avoid all technical terminology. If a technical term is \
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | {security_posture} | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | {threats_detected} | One sentence on whether this volume is typical or elevated
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and \
scan_limitations values from the scan data. Split each into \
individual line items — do not combine into a single cell. \
This is mandatory. Readers must immediately understand the \
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|

Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of: \
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report \
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation \
   of this type running this kind of system. Be specific — reference \
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated \
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like \
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something \
specific from the scan data.

#### 2. Network Fingerprint (Table)
Produce a Markdown table with exactly these five columns:
| Port / Protocol | Service Name | Function | Risk Assessment | Priority |
|---|---|---|---|---|

Column guidance:
- **Port / Protocol**: Format as `<number>/<PROTOCOL>` e.g. `80/TCP`
- **Service Name**: Service and version if available e.g. `HTTP / lighttpd 1.4`
- **Function**: One plain-English sentence — what does this service actually \
DO on the network? Avoid acronyms without explanation.
- **Risk Assessment**: `<Level> — <plain-English reason>`
  Risk levels in ascending order: Low / Medium / High / Critical
- **Priority**: Exactly one of: \
  Critical — Fix Now / High — Fix Soon / Medium — Monitor / Low — No Action Needed

#### 3. Deep Dive Analysis
- Cover the top 2–3 most significant or unusual findings.
- If Threats Detected > 0, those MUST appear first.
- For each finding follow this exact five-part structure:
  **a. What it is** — Name the port/service with a jargon-free explanation.
  **b. Why it may be open** — The likely legitimate reason this service is running.
  **c. What an attacker could do** — A concrete, realistic attack scenario written \
as a short story the user can picture. Do NOT use abstract language like \
"could be exploited." Use narrative form.
  **d. Urgency** — One sentence on how quickly this should be addressed, \
using the plain text priority label: Critical — Fix Now / High — Fix Soon / Medium — Monitor.
  **e. Business Impact Assessment**
  Produce a Markdown table with exactly these two columns:
  | Impact Dimension | Rating |
  |---|---|
  | Financial | Low / Medium / High |
  | Data Risk | Low / Medium / High |
  | Reputation | Low / Medium / High |
  Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose?

#### 4. Remediation & Hardening
- Provide exactly 3 bullet points ordered by priority: most critical first.
- Each bullet MUST follow this exact structure:
  **Issue**: [The specific port/service/risk this addresses]
  **Action**: [Plain step-by-step instructions a non-technical user can follow \
or hand off to support — no terminal commands or code]
  **Benefit**: [One sentence on what risk this eliminates]
  **Owner**: [Self / ISP / IT Support]

#### 5. Risk Score Breakdown
Produce a professional security scorecard using a Markdown table. Score each \
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is \
critically exposed. Derive all scores strictly from the scan data — do not \
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Open Ports
2. Threat Level
3. Service Risk
4. Exposure

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score \
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores, \
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Mark the path matching the Security Posture from [SCAN DATA] with [ YOU ARE HERE ]. \
Leave the others unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your network has serious vulnerabilities that need immediate attention.

→ Step 1: [Most urgent action — plain English, no jargon]
→ Step 2: [Second action]
→ Step 3: [Who to call or escalate to if self-resolution isn't possible]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your network has some exposure that should be addressed soon.

→ Step 1: [Most urgent action]
→ Step 2: [Second action]
→ Step 3: [Preventive measure or follow-up scan recommendation]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your network looks healthy. Keep up good habits.

→ Step 1: [Maintenance habit — e.g., schedule a re-scan]
→ Step 2: [One proactive hardening tip]
→ Step 3: [Long-term best practice]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit a path.
- Steps must be specific to the actual findings in [SCAN DATA], \
not generic boilerplate.
- The [ YOU ARE HERE ] marker appears on exactly ONE path.
- Timeline lines are fixed as shown — do not alter them.

================================================================================
[SCAN DATA]
================================================================================
Target Node        : {target_ip}
Scan Date          : {scan_date}
Scan Type          : {scan_type}
Scan Coverage      : {scan_coverage}
Scan Limitations   : {scan_limitations}
Security Posture   : {security_posture}
Threats Detected   : {threats_detected}
Total Open Ports   : {ports_found_count}

{ports_block}
================================================================================
[END OF SCAN DATA]
================================================================================
"""
    return prompt

def _format_traffic_analysis_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze TShark network traffic data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Session behaviour summary, baseline context, geo-context for external IPs,
        encryption status, capture window disclaimer, and owner-tagged remediation
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Core Data ---
    metadata          = parsed_data.get("scan_metadata", {})
    metrics           = parsed_data.get("traffic_metrics", {})
    protocols         = parsed_data.get("protocol_hierarchy", [])
    conversations     = parsed_data.get("active_conversations", [])
    packet_samples    = parsed_data.get("packet_sample", [])
    security_insights = parsed_data.get("security_insights", "N/A")

    target_node = metadata.get("target_node", "N/A")
    scan_date   = metadata.get("scan_date", "N/A")
    anomalies   = metadata.get("anomalies_detected", "Unknown")
    duration    = metrics.get("duration_sec", 0)
    volume      = metrics.get("data_volume", "N/A")
    throughput  = metrics.get("throughput", "N/A")

    # --- 2. Build Capture Window Disclaimer ---
    duration_label = f"{duration} seconds" if duration else "an unknown duration"
    scan_coverage = f"Network traffic captured over {duration_label} on the target node"
    scan_limitations = (
        "did NOT represent the device's full traffic history, activity on other "
        "devices, or any traffic outside the capture window"
    )

    # --- 3. Build Protocol Block ---
    if protocols:
        protocol_lines = ["### Protocol Hierarchy:"]
        for p in protocols:
            protocol_lines.append(
                f"- {p['protocol'].upper()}: {p['frames']} frames, {p['bytes']} bytes"
            )
        protocols_block = "\n".join(protocol_lines)
    else:
        protocols_block = "No protocol data available."

    # --- 4. Build Conversations Block ---
    if conversations:
        conv_lines = ["### Active Conversations:"]
        for c in conversations:
            conv_lines.append(
                f"- {c['src_ip']}:{c['src_port']} <--> {c['dst_ip']}:{c['dst_port']}"
            )
        conversations_block = "\n".join(conv_lines)
    else:
        conversations_block = "No conversation data available."

    # --- 4b. Build Packet Samples Block ---
    if packet_samples:
        pkt_lines = ["### Packet Threat Samples (AI Analyzed):"]
        for p in packet_samples:
            pkt_lines.append(
                f"- Seq: {p.get('source')} -> {p.get('destination')} ({p.get('protocol')}), "
                f"Threat Magnitude: {p.get('tctr_magnitude_percent', 'N/A')}%, "
                f"Intelligence: {p.get('intelligence_breakdown', 'N/A')}"
            )
        packets_block = "\n".join(pkt_lines)
    else:
        packets_block = "No packet analysis data available."

    # --- 5. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior Network Traffic Analyst** — an expert at making \
complex packet capture findings clear and actionable for everyday users, not just \
technical professionals.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the TShark packet capture data provided in the [CAPTURE DATA] block below \
and produce a professional "Traffic Inspection Briefing" report in exactly 6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "TLS (the encryption technology that scrambles your data so others \
cannot read it while it travels across the internet)"
  Example: "DNS (the internet's phone book — it translates website names like \
google.com into numeric addresses your device can connect to)"
- Treat the reader as an intelligent non-expert: someone who owns or manages a \
network but is NOT a cybersecurity professional.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [CAPTURE DATA] block. Do not invent IPs, \
ports, protocols, or verdicts not present in the data.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  Every Privacy Status label in the Protocol table (Section 2) MUST use \
exactly one of:
    Encrypted / Unencrypted / Mixed
5.  Every Connection Type label in the Connection table (Section 3) MUST use \
exactly one of:
    External / Internal
6.  Every Flag label in the Connection table (Section 3) MUST use exactly one of:
    Suspicious / Unusual / Normal
7.  If the Automated Verdict (Section 4) indicates any threat or anomaly, \
that finding MUST be addressed first in the Deep Dive within Section 4.
8.  All external IPs in the Connection Analysis (Section 3) MUST include a \
geo-context label derived by Gemini's knowledge:
    Format: <IP> → [Provider / Organisation, Country]
    Example: "142.250.80.46 → [Google LLC, United States]"
    If unknown, use: [Unknown Organisation]
9.  Remediation advice (Section 4) must be actionable steps a non-technical \
user can follow — no terminal commands or code snippets.
10. Every remediation point (Section 4) MUST end with an owner tag:
    **Owner: Self** | **Owner: ISP** | **Owner: IT Support**
11. Remediation points (Section 4) MUST be ordered by priority: \
highest-risk issue first.
12. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 decision paths: Critical / At Risk / Secure.
    b. Mark only the path matching the Automated Verdict with [ YOU ARE HERE ].
    c. All 3 paths must always be shown — never omit a path.
13. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
14. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary

Before the verdict paragraph, produce a Markdown metadata table with
exactly these two columns:
| Field | Value |
|---|---|
| Report Generated By | NetShieldAI Automated Security Analysis |
| Scan Target | {target_node} |
| Scan Date | {scan_date} |
| Capture Duration | {duration_label} |
| Total Data Transferred | {volume} |
| Average Throughput | {throughput} |
| Inferred Device Activity | [Determine based on dominant protocol] |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

Traffic Baseline Verdict: Include one sentence stating whether the observed \
traffic volume and throughput is normal or anomalous compared to what is \
expected for the inferred activity type.

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | {security_insights} | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Threat Signals | [count] | One sentence on whether this volume is typical or elevated
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|
Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. Protocol Composition (Table)
Produce a Markdown table with exactly these five columns:
| Protocol | Frame Count | Data Volume | % of Traffic | Privacy Status |
|---|---|---|---|---|

Column guidance:
- **Protocol**: Full name with plain-English role in parentheses.
  Example: "TLS (Encrypted Web Traffic)" / "DNS (Website Name Lookup)"
- **Frame Count**: As provided in the data.
- **Data Volume**: In bytes as provided.
- **% of Traffic**: Estimate as a percentage of total bytes across all protocols.
- **Privacy Status**: Exactly one of Encrypted / Unencrypted / Mixed

After the table, write 1–2 sentences interpreting what the protocol mix \
tells us about this device's privacy posture — is most traffic protected or exposed?

#### 3. Connection Analysis (Table + Flags)
Produce a Markdown table with exactly these six columns:
| Source | Destination | Geo-Context | Connection Type | Port Assessment | Flag |
|---|---|---|---|---|---|

Column guidance:
- **Source**: src_ip:src_port
- **Destination**: dst_ip:dst_port
- **Geo-Context**: For external IPs — [Provider / Organisation, Country]. \
For internal IPs — [Local Network Device]
- **Connection Type**: External / Internal
- **Port Assessment**: One plain-English sentence about the destination port.
  Example: "Port 443 — standard secure web port, expected" or \
"Port 4444 — non-standard, commonly used by remote access tools"
- **Flag**: Suspicious / Unusual / Normal

After the table, write 1–2 sentences summarising the external connection \
footprint — how many external destinations, any unexpected ones?

#### 4. Automated Security Insights & Recommendations
**Part A — Verdict Interpretation:**
- State the Automated Verdict from [CAPTURE DATA].
- Interpret it in plain English — what does this verdict actually mean for \
the user in terms of their day-to-day risk?
- If the verdict flags any threat or anomaly, explain it first using the \
same five-part structure as a Deep Dive:
  **a. What it is** — Plain-English explanation.
  **b. Why it may be happening** — Likely legitimate or malicious cause.
  **c. What an attacker could do** — Concrete narrative scenario, not abstract risk.
  **d. Urgency** — One sentence on timeline, using plain text priority: \
Critical — Fix Now / High — Fix Soon / Medium — Monitor / Low — No Action Needed
  **e. Business Impact Assessment**
  Produce a Markdown table with exactly these two columns:
  | Impact Dimension | Rating |
  |---|---|
  | Financial | Low / Medium / High |
  | Data Risk | Low / Medium / High |
  | Reputation | Low / Medium / High |
  Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose?

**Part B — Recommendations (exactly 3):**
- Order by priority: most critical first.
- Each point MUST follow this structure:
  **Issue**: [Specific protocol/connection/behaviour this addresses]
  **Action**: [Plain step-by-step — no commands or code]
  **Benefit**: [One sentence on what risk this eliminates]
  **Owner**: [Self / ISP / IT Support]

#### 5. Risk Score Breakdown
Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Encryption Rate
2. External Exposure
3. Threat Signals
4. Traffic Anomaly

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Match the path to the Automated Verdict from [CAPTURE DATA] and mark it \
with [ YOU ARE HERE ]. Leave the other two paths unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Suspicious traffic was detected that needs immediate investigation.

→ Step 1: [Most urgent action in plain English — specific to the findings]
→ Step 2: [Second action]
→ Step 3: [Who to call or escalate to]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Some unusual traffic patterns were found that warrant attention soon.

→ Step 1: [Most urgent action]
→ Step 2: [Second action]
→ Step 3: [Preventive measure or follow-up scan recommendation]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Traffic looks clean and expected. Keep up good habits.

→ Step 1: [Maintenance habit — e.g., schedule a re-capture]
→ Step 2: [One proactive privacy tip based on the protocol mix]
→ Step 3: [Long-term best practice]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must be specific to the actual findings in [CAPTURE DATA], \
not generic boilerplate.
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed as shown — do not alter them.

================================================================================
[CAPTURE DATA]
================================================================================
Target Node          : {target_node}
Scan Date            : {scan_date}
Capture Duration     : {duration_label}
Total Data Volume    : {volume}
Throughput           : {throughput}
Anomalies Detected   : {anomalies}
Automated Verdict    : {security_insights}
Scan Coverage        : {scan_coverage}
Scan Limitations     : {scan_limitations}

{protocols_block}

{conversations_block}

{packets_block}
================================================================================
[END OF CAPTURE DATA]
================================================================================
"""
    return prompt

def _format_zap_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze NetShieldAI (ZAP) web scan data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Enforced per-finding structure with attacker narratives and business impact scoring
      - Owner-tagged, timeline-aware remediation checklist
      - Effort-vs-benefit tagging for low risk findings
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Core Data ---
    metadata     = parsed_data.get("scan_metadata", {})
    risk_counts  = parsed_data.get("alert_summary", {})
    findings     = parsed_data.get("findings", [])

    target_url         = metadata.get("target_url", "N/A")
    generated_at       = metadata.get("generated_at", "N/A")
    risk_magnitude     = metadata.get("risk_magnitude", "N/A")
    tool               = metadata.get("tool", "ZAP Scanner")
    endpoints_tested   = metadata.get("endpoints_tested", "Unknown")
    authenticated_scan = metadata.get("authenticated_scan", "Unknown")

    # --- 2. Separate Findings by Risk Level ---
    high_medium_findings = [
        f for f in findings
        if f.get("risk_level", "").upper() in ["HIGH", "MEDIUM"]
    ]
    # Sort: HIGH always before MEDIUM
    high_medium_findings.sort(
        key=lambda f: 0 if f.get("risk_level", "").upper() == "HIGH" else 1
    )

    low_info_findings = [
        f for f in findings
        if f.get("risk_level", "").upper() in ["LOW", "INFO", "INFORMATIONAL"]
    ]

    # --- 3. Build Risk Count Block ---
    risk_count_lines = ["### Alert Summary:"]
    for level, count in risk_counts.items():
        if level != "Total":
            risk_count_lines.append(f"- {level}: {count}")
    risk_count_block = "\n".join(risk_count_lines)

    # --- 4. Build High & Medium Findings Block ---
    if high_medium_findings:
        hm_lines = ["### High & Medium Risk Findings:"]
        for i, f in enumerate(high_medium_findings, 1):
            hm_lines.append(f"--- FINDING #{i} ---")
            hm_lines.append(f"Name        : {f.get('name', 'N/A')}")
            hm_lines.append(f"Risk Level  : {f.get('risk_level', 'N/A')}")
            hm_lines.append(f"Affected URL: {f.get('url', 'N/A')}")
            hm_lines.append(f"Description : {f.get('description', 'N/A')}")
            hm_lines.append(f"Solution    : {f.get('solution', 'N/A')}")
            hm_lines.append(f"Threat Mag  : {f.get('tctr_magnitude_percent', 'N/A')}%")
            hm_lines.append(f"Intelligence: {f.get('intelligence_breakdown', 'N/A')}\n")
        high_medium_block = "\n".join(hm_lines)
    else:
        high_medium_block = "### High & Medium Risk Findings:\nNo critical vulnerabilities found."

    # --- 5. Build Low & Info Findings Block (deduplicated) ---
    if low_info_findings:
        low_lines  = ["### Low & Informational Findings:"]
        seen_names = set()
        for f in low_info_findings:
            name = f.get("name", "N/A")
            risk = f.get("risk_level", "N/A")
            if name not in seen_names:
                low_lines.append(
                    f"- {name} (Risk Level: {risk}) | "
                    f"Threat Mag: {f.get('tctr_magnitude_percent', 'N/A')}% | "
                    f"Intelligence: {f.get('intelligence_breakdown', 'N/A')}"
                )
                seen_names.add(name)
        low_block = "\n".join(low_lines)
    else:
        low_block = "### Low & Informational Findings:\nNo low or informational findings."

    # --- 6. Build Scan Coverage & Limitations ---
    scan_coverage = (
        "Publicly accessible web endpoints, HTTP headers, and known "
        "vulnerability signatures detectable via automated scanning"
    )
    scan_limitations = (
        "Business logic flaws, authentication bypass via manual techniques, "
        "server-side source code vulnerabilities, or issues behind login-protected pages "
        "(unless authenticated scanning was configured)"
    )

    # --- 7. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior Web Application Security Consultant** — an expert \
at making complex web vulnerability findings clear and actionable for both \
business owners and development teams, not just security professionals.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the OWASP ZAP scan data provided in the [SCAN DATA] block below and \
produce a professional "Web Application Security Briefing" report in exactly \
6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "SQL Injection (a technique where an attacker types specially crafted \
text into a form field to trick your database into handing over its contents)"
  Example: "XSS — Cross-Site Scripting (a method where attackers hide malicious \
instructions in your web page that run inside a visitor's browser)"
  Example: "HTTP Security Header (an invisible instruction your web server sends \
to browsers telling them how to handle your site safely)"
- Write for two audiences simultaneously:
  • Business Owner: Needs to understand the RISK and BUSINESS IMPACT.
  • Developer: Needs the TECHNICAL DETAIL and SPECIFIC FIX.
  Serve both in every finding — do not choose one over the other.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [SCAN DATA] block. Do not invent URLs, \
parameters, or vulnerabilities not present in the data.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  High risk findings MUST always appear before Medium risk findings in \
Section 2. The data block is already sorted — maintain that order.
5.  Every finding in Section 2 MUST follow the exact five-part structure \
defined in the Section 2 instructions — no exceptions.
6.  The attacker scenario in Section 2 (part c) MUST be written as a \
concrete short story — do NOT use abstract language like "could be exploited" \
or "may allow attackers to." Use narrative form the business owner can picture.
7.  The Remediation Checklist table (Section 3) MUST include exactly these \
columns: Priority | Action Item | Affected Component | Difficulty | Owner | Timeline.
8.  Every Owner cell in Section 3 MUST use exactly one of:
    Dev Team / IT Support / Both
9.  Every Timeline cell in Section 3 MUST use exactly one of:
    Critical — Immediate / High — This Sprint / Medium — This Quarter / Low — When Possible
10. Every item in the Low Risk section (Section 4) MUST end with an \
effort-vs-benefit tag on the same line:
    [Effort: Low/Medium/High | Benefit: Low/Medium/High]
11. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 paths: Critical / At Risk / Secure.
    b. Mark only the path matching the overall risk status with [ YOU ARE HERE ].
    c. Always show all 3 paths — never omit one.
12. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
13. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary

Before the verdict paragraph, produce a Markdown metadata table with
exactly these two columns:
| Field | Value |
|---|---|
| Report Generated By | {tool} |
| Scan Target | {target_url} |
| Scan Date | {generated_at} |
| Scan Tool | {tool} |
| Endpoints Tested | {endpoints_tested} |
| Authenticated Scan | {authenticated_scan} |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | [Secure / At Risk / Critical] | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | [count] | One sentence on whether this volume is typical or elevated
- Alert Distribution | [High: X, Medium: Y, Low: Z, Info: W] | One sentence on what the balance of finding severities suggests
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|

Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. Critical Vulnerability Analysis (High & Medium Only)
For each finding in the [SCAN DATA] High & Medium block, follow this EXACT \
five-part structure — no deviation:

**Finding #[N] — [Vulnerability Name] | HIGH / MEDIUM**

**a. Plain-English Explanation**
What is this vulnerability? Write 2–3 sentences as if explaining to someone \
with no technical background. Use an analogy if it helps.
Include the jargon term in parentheses after the plain-English name.

**b. Business Impact Assessment**
Produce a Markdown table with exactly these two columns:
| Impact Dimension | Rating |
|---|---|
| Financial | Low / Medium / High |
| Data Risk | Low / Medium / High |
| Reputation | Low / Medium / High |

Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose?

**c. Attacker Scenario**
Write a concrete, realistic short story (3–5 sentences) describing exactly \
what an attacker would do and what they would gain. Do NOT use abstract \
language like "could be exploited." Use narrative form:
Example: "A malicious user visits your login page and instead of typing a \
password, types a specially crafted string into the username field. Your \
database interprets this as a command rather than input, and instantly returns \
every username, password hash, and email address it contains. The attacker \
downloads this list, cracks the passwords offline, and logs in as any user — \
including administrators."

**d. Technical Details**
- Affected URL: [from scan data]
- Vulnerable Component: [parameter, header, or endpoint]
- Attack Vector: [how the attacker delivers the payload]

**e. Developer Fix**
Provide specific, actionable technical guidance. Reference the exact \
URL/parameter from the scan data. Write in plain steps a developer can \
act on immediately — but still explain WHY each step works so a non-developer \
reading over their shoulder understands it.
Do NOT include raw code blocks.

#### 3. Prioritized Remediation Checklist (Table)
Produce a Markdown table with exactly these six columns:
| Priority | Action Item | Affected Component | Difficulty | Owner | Timeline |
|---|---|---|---|---|---|

Column guidance:
- **Priority**: 1 = most critical, ascending.
- **Action Item**: Plain-English description of the fix — no jargon without explanation.
- **Affected Component**: Specific URL, header, or parameter from the scan data.
- **Difficulty**: Low / Medium / High — how hard is this fix to implement?
- **Owner**: Dev Team / IT Support / Both
- **Timeline**: Critical — Immediate / High — This Sprint / Medium — This Quarter / Low — When Possible

After the table, write one sentence summarising the overall remediation effort — \
is this a quick afternoon of fixes or a multi-sprint effort?

#### 4. Low Risk & Best Practices
- List every unique low / informational finding from the [SCAN DATA] low block.
- For each item write one plain-English sentence explaining what it is and \
why it matters — do not just repeat the finding name.
- End each item on the same line with an effort-vs-benefit tag:
  [Effort: Low/Medium/High | Benefit: Low/Medium/High]
- After the list, write 1–2 sentences advising which items to prioritise \
based on effort vs. benefit — guide the reader to the quick wins.

#### 5. Risk Score Breakdown
Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Injection Risk
2. Authentication
3. Security Headers
4. Overall Exposure

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Determine the overall status from the risk counts in [SCAN DATA] — \
if any HIGH findings exist → Critical, if only MEDIUM → At Risk, \
if none → Secure. Mark the matching path with [ YOU ARE HERE ].

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your web application has serious vulnerabilities that could be actively exploited.

→ Step 1: [Most urgent fix — specific to the highest-risk finding in the data]
→ Step 2: [Second most urgent action]
→ Step 3: [Who to escalate to if the dev team cannot fix immediately]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your application has medium-severity issues that should be addressed soon.

→ Step 1: [Most urgent medium-risk fix from the data]
→ Step 2: [Second action]
→ Step 3: [Preventive measure or recommended follow-up scan]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No critical issues found. Focus on maintaining and improving your security posture.

→ Step 1: [Address any low-risk quick wins from Section 4]
→ Step 2: [One proactive hardening recommendation based on the scan data]
→ Step 3: [Long-term best practice — e.g., schedule regular scans]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must reference actual findings from [SCAN DATA] — not generic boilerplate.
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed as shown — do not alter them.
- Overall status determination logic: ANY High finding → Critical path. \
No High but Medium exists → At Risk path. Neither → Secure path.

================================================================================
[SCAN DATA]
================================================================================
Target URL         : {target_url}
Scan Date          : {generated_at}
Risk Magnitude     : {risk_magnitude}
Tool               : {tool}
Endpoints Tested   : {endpoints_tested}
Authenticated Scan : {authenticated_scan}
Scan Coverage      : {scan_coverage}
Scan Limitations   : {scan_limitations}

{risk_count_block}

{high_medium_block}

{low_block}
================================================================================
[END OF SCAN DATA]
================================================================================
"""
    return prompt

def _format_sslscan_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze NetShieldAI (SSLScan) data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Enforced per-finding structure with attacker narratives and business impact scoring
      - Certificate expiry urgency flag built in Python before injection
      - Owner-tagged, timeline-aware remediation plan (no config commands)
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Core Data ---
    meta            = parsed_data.get("metadata", {})
    cert            = parsed_data.get("certificate_chain", {})
    config          = parsed_data.get("server_configuration", {})
    vulns           = parsed_data.get("vulnerabilities", [])
    protocols_dict  = parsed_data.get("protocols", {})

    target    = meta.get("target", "Unknown")
    scan_date = meta.get("scan_date", "Unknown")
    grade     = meta.get("grade", "N/A")

    # --- 2. Identify Weak Ciphers & Active Protocols ---
    weak_ciphers     = []
    active_protocols = []

    for proto, ciphers in protocols_dict.items():
        active_protocols.append(proto)
        for c in ciphers:
            name = c.get("cipher", "")
            bits = c.get("bits", 0)
            if bits < 128 or any(tag in name for tag in ["DES", "RC4", "MD5", "NULL", "EXPORT"]):
                weak_ciphers.append(f"{proto}: {name} ({bits} bits)")

    # --- 3. Separate Vulnerabilities by Severity ---
    high_med_vulns = [
        v for v in vulns
        if v.get("severity", "").upper() in ["HIGH", "MEDIUM", "CRITICAL"]
    ]
    # Sort: CRITICAL first, then HIGH, then MEDIUM
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    high_med_vulns.sort(key=lambda v: severity_order.get(v.get("severity", "").upper(), 99))

    low_info_vulns = [
        v for v in vulns
        if v.get("severity", "").upper() in ["LOW", "INFO", "INFORMATIONAL"]
    ]

    # --- 4. Build Certificate Expiry Urgency Flag (Plain Text) ---
    expiry_raw = cert.get("leaf_expiry", "N/A")
    try:
        from datetime import datetime, timezone
        expiry_dt  = datetime.strptime(expiry_raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        today      = datetime.now(timezone.utc)
        days_left  = (expiry_dt - today).days

        if days_left < 0:
            expiry_urgency = f"Critical — EXPIRED {abs(days_left)} days ago — immediate renewal required"
        elif days_left <= 7:
            expiry_urgency = f"Critical — expires in {days_left} day(s), renew immediately"
        elif days_left <= 30:
            expiry_urgency = f"High — WARNING — expires in {days_left} days, renew this week"
        elif days_left <= 90:
            expiry_urgency = f"Medium — MONITOR — expires in {days_left} days, schedule renewal soon"
        else:
            expiry_urgency = f"Low — VALID — {days_left} days remaining, no action needed"
    except (ValueError, TypeError):
        expiry_urgency = "Unknown — expiry date could not be parsed"

    # --- 5. Build Scan Coverage Disclaimer (Split for tables) ---
    scan_coverage = (
        "SSL/TLS protocol support, cipher suite strength, certificate "
        "validity, and known cryptographic vulnerabilities"
    )
    scan_limitations = (
        "Application-layer security, authentication mechanisms, firewall rules, "
        "server-side code vulnerabilities, or any non-SSL/TLS attack surfaces"
    )

    # --- 6. Build Vulnerabilities Block ---
    if high_med_vulns:
        vuln_lines = ["### High / Medium / Critical Vulnerabilities:"]
        for i, v in enumerate(high_med_vulns, 1):
            vuln_lines.append(f"--- VULNERABILITY #{i} ---")
            vuln_lines.append(f"Name        : {v.get('name', 'N/A')}")
            vuln_lines.append(f"Severity    : {v.get('severity', 'N/A')}")
            vuln_lines.append(f"Description : {v.get('description', 'N/A')}")
            vuln_lines.append(f"Threat Mag  : {v.get('tctr_magnitude_percent', 'N/A')}%")
            vuln_lines.append(f"Intelligence: {v.get('intelligence_breakdown', 'N/A')}\n")
        vuln_block = "\n".join(vuln_lines)
    else:
        vuln_block = "### High / Medium / Critical Vulnerabilities:\nNone detected."

    if low_info_vulns:
        low_lines  = ["### Low / Informational Vulnerabilities:"]
        seen_names = set()
        for v in low_info_vulns:
            name = v.get("name", "N/A")
            if name not in seen_names:
                low_lines.append(
                    f"- {name} (Severity: {v.get('severity', 'N/A')}) | "
                    f"Threat Mag: {v.get('tctr_magnitude_percent', 'N/A')}% | "
                    f"Intelligence: {v.get('intelligence_breakdown', 'N/A')}"
                )
                seen_names.add(name)
        low_vuln_block = "\n".join(low_lines)
    else:
        low_vuln_block = "### Low / Informational Vulnerabilities:\nNone detected."

    # --- 7. Build Weak Ciphers Block ---
    weak_cipher_block = (
        "### Weak Ciphers Detected:\n" +
        ("\n".join(f"- {wc}" for wc in weak_ciphers) if weak_ciphers
         else "None detected — all active ciphers meet minimum strength requirements.")
    )

    # --- 8. Build Active Protocols Block ---
    protocols_block = (
        "### Active Protocols:\n- " + "\n- ".join(active_protocols)
        if active_protocols else "### Active Protocols:\nNo protocol data available."
    )

    # --- 9. Build Server Configuration Block ---
    if config:
        config_lines = ["### Server Configuration:"]
        for k, v in config.items():
            config_lines.append(f"- {k}: {v}")
        config_block = "\n".join(config_lines)
    else:
        config_block = "### Server Configuration:\nNo configuration data available."

    # --- 10. Build Certificate Block ---
    cert_block = f"""\
### Certificate Details:
- Subject             : {cert.get('subject', 'N/A')}
- Issuer              : {cert.get('issuer', 'N/A')}
- Expiry              : {expiry_raw}
- Expiry Urgency      : {expiry_urgency}
- Signature Algorithm : {cert.get('signature_algorithm', 'N/A')}
- Key Type            : {cert.get('key_type', 'N/A')}"""

    # --- 11. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior SSL/TLS Security Consultant** — an expert at \
making complex encryption and certificate findings clear and actionable for \
both business owners and development teams, not just security professionals.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the SSLScan data provided in the [SCAN DATA] block below and produce \
a professional "SSL/TLS Security Briefing" report in exactly 6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "TLS 1.0 (an older version of the encryption standard used to \
protect data in transit — now considered unsafe because researchers have \
found ways to break it)"
  Example: "Cipher Suite (the specific combination of mathematical recipes \
your server and a visitor's browser agree to use when scrambling data \
between them)"
  Example: "Certificate (a digital ID card that proves your website is \
genuinely yours and enables encrypted connections)"
  Example: "RC4 (an outdated encryption method that has known weaknesses — \
attackers can use these weaknesses to slowly decode protected traffic)"
- Write for two audiences simultaneously:
  • Business Owner: Needs to understand RISK and BUSINESS IMPACT.
  • Developer / IT Admin: Needs TECHNICAL DETAIL and SPECIFIC FIX.
  Serve both in every finding.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [SCAN DATA] block. Do not invent \
vulnerabilities, protocols, or cipher names not present in the data.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  Vulnerability severity order in Section 2 MUST be: \
CRITICAL first, then HIGH, then MEDIUM. The data block is pre-sorted — \
maintain that order.
5.  Every vulnerability in Section 2 MUST follow the exact four-part \
structure defined in the Section 2 instructions — no exceptions.
6.  The attacker scenario in Section 2 (part c) MUST be a concrete short \
story in narrative form — do NOT use abstract language like \
"could be exploited" or "may allow downgrade attacks."
7.  The Protocol & Cipher table in Section 3 MUST include a \
Privacy Implication column explaining in plain English what each \
protocol's status means for data privacy.
8.  The Certificate Health section (Section 4) MUST:
    a. Use the pre-computed Expiry Urgency flag from [SCAN DATA] verbatim.
    b. Interpret the Signature Algorithm and Key Type in plain English — \
do not just restate the raw value.
    c. State clearly whether the certificate is fit for purpose or \
needs immediate attention.
9.  Remediation steps (Section 5) MUST be ordered by priority: \
most critical first. Wait, Section 5 is Risk Score Breakdown and Section \
6 is Decision Guide. Follow section order strictly.
10. Do NOT include terminal commands, config file syntax, or code \
write plain-English steps only.
11. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 paths: Critical / At Risk / Secure.
    b. Determine the correct path using this logic:
       - ANY Critical or High vulnerability present → Critical path
       - No Critical/High but Medium vulnerability OR deprecated protocol active → At Risk path
       - Neither condition → Secure path
    c. Mark the matching path with [ YOU ARE HERE ].
    d. Always show all 3 paths — never omit one.
12. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
13. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary

Before the verdict paragraph, produce a Markdown metadata table with
exactly these two columns:
| Field | Value |
|---|---|
| Report Generated By | SSLScan |
| Scan Target | {target} |
| Scan Date | {scan_date} |
| Certificate Expiry Status | {expiry_urgency} |
| Overall SSL/TLS Grade | {grade} |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

Protocol Support Summary: Add one sentence stating how many protocols are \
active and whether any are deprecated.

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | [Secure / At Risk / Critical] | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | [count] | One sentence on whether this volume is typical or elevated
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|

Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. Critical Vulnerability Analysis (Critical, High & Medium Only)
For each vulnerability in the [SCAN DATA] high/medium block, follow this \
EXACT four-part structure:

**Vulnerability #[N] — [Name] | CRITICAL / HIGH / MEDIUM**

**a. Plain-English Explanation**
What is this vulnerability? Write 2–3 sentences for a non-technical reader. \
Use an analogy if it helps. Always include the technical name in parentheses \
after the plain-English description.

**b. Business Impact Assessment**
Produce a Markdown table with exactly these two columns:
| Impact Dimension | Rating |
|---|---|
| Financial | Low / Medium / High |
| Data Risk | Low / Medium / High |
| Reputation | Low / Medium / High |

Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose if this is exploited?

**c. Attacker Scenario**
Write a concrete, realistic short story (3–5 sentences) in plain English. \
Do NOT use abstract language. Describe exactly what an attacker would do \
step by step and what they would gain.
Example: "An attacker at the same coffee shop as one of your customers \
intercepts the encrypted connection. Because your server still supports \
TLS 1.0, the attacker tricks both sides into using this older, weaker \
encryption. Over the next few minutes, they quietly decode the session \
and read the customer's login credentials and payment details in plain text."

**d. Technical Fix Guidance**
- What specifically needs to be changed on the server.
- Why this fix works — explained so a non-developer reading over the \
IT admin's shoulder understands the reasoning.
- Written as plain steps — no config syntax or terminal commands.

#### 3. Protocol & Cipher Analysis (Tables)

**Part A — Protocol Support Table**
Produce a Markdown table with exactly these five columns:
| Protocol | Version Status | Security Status | Privacy Implication | Recommended Action |
|---|---|---|---|---|

Column guidance:
- **Protocol**: Full name e.g. "TLS 1.3", "TLS 1.0", "SSL 3.0"
- **Version Status**: Current / Deprecated / Obsolete
- **Security Status**: Secure / Acceptable / Risky / Dangerous
- **Privacy Implication**: One plain-English sentence — what does \
supporting or not supporting this protocol mean for the privacy of \
data traveling between the server and a visitor's browser?
- **Recommended Action**: Keep / Disable / Upgrade

**Part B — Weak Cipher Summary**
If weak ciphers are present in [SCAN DATA]:
- List each weak cipher with a plain-English explanation of why it is weak.
  Example: "RC4 — once considered fast and secure, researchers discovered \
in 2013 that patterns in its output can be used to slowly decode \
protected messages."
- State clearly what category of cipher should replace it.
If no weak ciphers: confirm the cipher configuration is healthy.

#### 4. Configuration & Certificate Health

**Part A — Server Configuration Review**
For each configuration flag in [SCAN DATA]:
- State what the flag is in plain English.
- State whether its current value is Secure or a Risk.
- One sentence on why it matters.

**Part B — Certificate Health**
Produce a Markdown table with exactly these columns:
| Field | Value | Plain-English Meaning | Health Status |
|---|---|---|---|

Rows: Subject, Issuer, Expiry, Signature Algorithm, Key Type.

Rules:
- Use the Expiry Urgency flag from [SCAN DATA] verbatim in the \
Health Status cell for the Expiry row.
- Interpret Signature Algorithm in plain English — e.g., \
"SHA-256 (a modern, secure hashing method — your certificate \
fingerprint cannot be forged)"
- Interpret Key Type in plain English — e.g., \
"RSA-2048 (a widely trusted key length — considered secure for \
general use until at least 2030)"
- End Part B with a one-sentence overall certificate verdict: \
is this certificate fit for purpose right now?

#### 5. Risk Score Breakdown

Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Protocol Strength
2. Cipher Suite
3. Certificate Health
4. Known Vulnerabilities

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Determine the correct path from [SCAN DATA] using this logic:
- ANY Critical or High vulnerability present → Critical path
- No Critical/High but Medium vulnerability OR deprecated protocol \
active → At Risk path
- Neither condition → Secure path
Mark the correct path with [ YOU ARE HERE ]. Leave others unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your server's encryption has serious weaknesses that could expose \
your users' data right now.

→ Step 1: [Most urgent action — specific to highest severity finding]
→ Step 2: [Second action — specific to scan data]
→ Step 3: [Who to escalate to if immediate fix is not possible]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your encryption is functional but has configuration gaps that \
should be addressed soon.

→ Step 1: [Most urgent medium-risk or deprecated protocol fix]
→ Step 2: [Second action — specific to scan data]
→ Step 3: [Preventive measure or recommended follow-up scan]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your SSL/TLS configuration is in good shape. Focus on maintaining it.

→ Step 1: [Certificate renewal reminder or monitoring recommendation]
→ Step 2: [One proactive hardening tip based on scan data]
→ Step 3: [Long-term best practice — e.g., schedule quarterly scans]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must reference actual findings from [SCAN DATA].
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed — do not alter them.

================================================================================
[SCAN DATA]
================================================================================
Target             : {target}
Scan Date          : {scan_date}
Overall Grade      : {grade}
Scan Coverage      : {scan_coverage}
Scan Limitations   : {scan_limitations}

{vuln_block}

{low_vuln_block}

{weak_cipher_block}

{protocols_block}

{config_block}

{cert_block}
================================================================================
[END OF SCAN DATA]
================================================================================
"""
    return prompt

def _format_sql_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze NetShieldAI SQL Injection audit data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Privileged user escalation trigger built in Python before injection
      - Enforced per-finding structure with attacker narratives and business impact scoring
      - Priority-sorted vulnerabilities: CRITICAL → HIGH → MEDIUM
      - Owner-tagged, timeline-aware remediation plan (no code snippets)
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Core Data ---
    meta        = parsed_data.get("metadata", {})
    counts      = parsed_data.get("summary_counts", {})
    fingerprint = parsed_data.get("database_fingerprint", {})
    vulns       = parsed_data.get("vulnerabilities", [])

    target_url      = meta.get("target_url", "Unknown")
    scan_date       = meta.get("scan_date", "Unknown")
    db_status       = meta.get("audit_status", "Unknown")
    ml_threat_index = meta.get("ml_threat_index", "N/A")

    vuln_count       = counts.get("vulnerabilities_found", 0)
    injection_types  = counts.get("injection_types_count", 0)

    detected_dbms    = fingerprint.get("detected_dbms", "Unknown")
    db_version       = fingerprint.get("version", "Unknown")
    current_user     = fingerprint.get("current_user", "Unknown")
    current_database = fingerprint.get("current_database", "Unknown")

    # --- 2. Privileged User Escalation Flag (Plain Text) ---
    user_lower    = current_user.lower()
    is_privileged = any(tag in user_lower for tag in ["root", "admin", "dba", "sa", "superuser"])

    if is_privileged:
        privilege_flag = (
            f"CRITICAL PRIVILEGE ALERT: The database is running as '{current_user}' — "
            f"a highly privileged account. An attacker exploiting this injection does not "
            f"just read data — they may have full control over the entire database, "
            f"including the ability to delete all records, create backdoor accounts, "
            f"read files from the server, or execute system-level commands depending "
            f"on the database technology in use."
        )
        privilege_meta_row = (
            f"| CRITICAL PRIVILEGE ALERT | Active — Database Technology: {detected_dbms}, "
            f"Current DB: {current_database}, Injection Types Detected: {injection_types} |"
        )
    else:
        privilege_flag = (
            f"STANDARD PRIVILEGE: The database is running as '{current_user}' — "
            f"a standard (non-admin) account. Exploitation is still serious but the "
            f"attacker's reach is limited to the data accessible by this user."
        )
        privilege_meta_row = ""

    # --- 3. Priority-Sort Vulnerabilities: CRITICAL → HIGH → MEDIUM → LOW ---
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(
        vulns,
        key=lambda v: severity_order.get(v.get("risk_level", "").upper(), 99)
    )

    # --- 4. Build Vulnerabilities Block ---
    if sorted_vulns:
        vuln_lines = ["### Detected Injection Vectors (sorted by severity):"]
        for i, v in enumerate(sorted_vulns, 1):
            payload = v.get("payload", "N/A")
            if len(payload) > 150:
                payload = payload[:147] + "..."
            vuln_lines.append(f"--- FINDING #{i} ---")
            vuln_lines.append(f"Risk Level      : {v.get('risk_level', 'N/A')}")
            vuln_lines.append(f"Injection Type  : {v.get('injection_type', 'N/A')}")
            vuln_lines.append(f"Title           : {v.get('title', 'N/A')}")
            vuln_lines.append(f"Payload Sample  : {payload}")
            vuln_lines.append(f"Remediation Hint: {v.get('remediation', 'N/A')}\n")
        vuln_block = "\n".join(vuln_lines)
    else:
        vuln_block = "### Detected Injection Vectors:\nNo injection vulnerabilities found."

    # --- 5. Build Scan Coverage & Limitations ---
    scan_coverage = (
        "SQL injection vulnerability detection across the "
        "target's input parameters, forms, and URL endpoints"
    )
    scan_limitations = (
        "Other web vulnerabilities (XSS, CSRF, authentication bypass), internal "
        "network access, server-side code logic flaws, or endpoints that require "
        "authenticated session access (unless authenticated scanning was configured)"
    )

    # --- 6. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior Database Security Consultant** — an expert at \
making complex SQL injection findings clear and actionable for both business \
owners and development teams, not just security professionals.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the SQL Injection Audit data provided in the [SCAN DATA] block below \
and produce a professional "Database Security Briefing" report in exactly \
6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "SQL Injection (a technique where an attacker types specially \
crafted text into a form or URL to trick your database into obeying their \
commands instead of your application's)"
  Example: "Boolean-Based Blind Injection (a method where the attacker asks \
your database true/false questions thousands of times to slowly piece \
together its contents — like guessing a combination lock one digit at a time)"
  Example: "Time-Based Blind Injection (a technique where the attacker makes \
your database pause deliberately to confirm whether their guess was correct \
— like Morse code through your server's response time)"
  Example: "UNION-Based Injection (a method where the attacker appends their \
own database query onto yours, forcing your application to display data it \
was never meant to show)"
  Example: "Prepared Statement (a secure coding technique where the \
application tells the database the shape of a query before any user input \
is added — making it impossible for input to be treated as a command)"
- Write for two audiences simultaneously:
  • Business Owner: Needs to understand RISK, DATA EXPOSURE, and BUSINESS IMPACT.
  • Developer / DBA: Needs TECHNICAL CONTEXT and SPECIFIC FIX DIRECTION.
  Serve both in every finding.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [SCAN DATA] block. Do not invent \
injection types, payloads, or database details not present in the data.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  If the [SCAN DATA] Privilege Flag contains CRITICAL PRIVILEGE ALERT, \
the Executive Summary (Section 1) MUST open with that alert prominently \
before any other content — this is the single most dangerous condition \
in a SQL injection audit.
5.  Vulnerability order in Section 3 MUST follow: \
CRITICAL → HIGH → MEDIUM → LOW. The data block is pre-sorted — \
maintain that order.
6.  Every finding in Section 3 MUST follow the exact four-part structure \
defined in the Section 3 instructions — no exceptions.
7.  The attacker scenario in Section 3 (part c) MUST be a concrete short \
story in narrative form — do NOT use abstract language like \
"could allow data extraction" or "may enable unauthorized access."
8.  The vulnerability summary table in Section 3 MUST use exactly these \
columns — replacing the raw payload column with a plain-English technique \
description:
    | # | Risk Level | Injection Type | What This Technique Does | Priority |
9.  Every remediation item (Section 4) MUST follow the exact structure \
defined in Section 4 and end with Owner and Timeline tags.
10. Do NOT include code snippets, prepared statement syntax, or terminal \
commands in Section 4 — plain-English steps only.
11. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 paths: Critical / At Risk / Secure.
    b. Use this path determination logic:
       - Database Status is 'Exposed' OR Privilege Flag indicates CRITICAL → Critical path
       - Database Status is not 'Exposed' but vulnerabilities exist → At Risk path
       - No vulnerabilities found → Secure path
    c. Mark the matching path with [ YOU ARE HERE ].
    d. Always show all 3 paths — never omit one.
12. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
13. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary

Before the verdict paragraph, produce a Markdown metadata table with
exactly these columns:
| Field | Value |
|---|---|
| Report Generated By | NetShieldAI SQL Injection Auditor |
| Scan Target | {target_url} |
| Scan Date | {scan_date} |
{privilege_meta_row}
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

Data at Risk Statement: Add one sentence stating what category of data is \
likely stored in the database based on its name ({current_database}).

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | [Secure / At Risk / Critical] | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | {vuln_count} | One sentence on whether this volume is typical or elevated
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|
Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. Target Fingerprint Analysis
Produce a Markdown table with exactly these columns:
| Property | Value | Plain-English Meaning | Risk Implication |
|---|---|---|---|

Rows: DBMS Technology, Version, Current User, Current Database.

Column guidance:
- **Plain-English Meaning**: What is this, explained simply?
  Example for DBMS: "MySQL is one of the most widely used database \
systems in the world — it stores your application's users, orders, \
content, and any other structured data."
  Example for Version: "Version 5.7 is an older release. Knowing the \
exact version lets an attacker look up published attack techniques \
that specifically target this version."
- **Risk Implication**: What does this specific value mean for the \
attacker's capability?
  For the Current User row: reproduce the full Privilege Flag from \
[SCAN DATA] verbatim in this cell.
  For the Current Database row: state what category of data is likely \
stored here based on the database name, and therefore what is at risk.

After the table, write 1–2 sentences summarising the combined fingerprint \
risk — what does knowing all four of these properties together give an attacker?

#### 3. Injection Vulnerability Analysis

**Part A — Summary Table**
Produce a Markdown table with exactly these five columns:
| # | Risk Level | Injection Type | What This Technique Does | Priority |
|---|---|---|---|---|

Column guidance:
- **Injection Type**: Technical name from scan data.
- **What This Technique Does**: One plain-English sentence — describe \
what the attacker is actually doing with this technique, without jargon.
  Example: "Asks the database thousands of true/false questions to \
reconstruct its contents one piece at a time."
- **Priority**: Critical — Fix Now / High — Fix Soon / Medium — Monitor / Low — No Action Needed

**Part B — Deep Dive Per Finding**
For each finding in [SCAN DATA], follow this EXACT four-part structure:

**Finding #[N] — [Title] | CRITICAL / HIGH / MEDIUM / LOW**

**a. Plain-English Explanation**
What is this injection technique? Write 2–3 sentences for a non-technical \
reader. Use the jargon-free examples from the ROLE block as a model. \
Include the technical name in parentheses after the plain-English description.

**b. Business Impact Assessment**
Produce a Markdown table with exactly these two columns:
| Impact Dimension | Rating |
|---|---|
| Financial | Low / Medium / High |
| Data Risk | Low / Medium / High |
| Reputation | Low / Medium / High |

Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose? Reference the current database \
name and privilege level from [SCAN DATA].

**c. Attacker Scenario**
Write a concrete, realistic short story (3–5 sentences) in plain English. \
Do NOT use abstract language. Walk through exactly what an attacker \
would do step by step using this specific technique and what they \
would gain given the privilege level detected.
If the privilege flag is CRITICAL, the scenario MUST include \
what happens BEYOND data theft — e.g., dropping tables, creating \
backdoor accounts, reading server files.

**d. Fix Direction**
- What the developer or DBA needs to address — in plain English.
- Why this fix works, explained so a non-developer can understand \
the reasoning.
- No code syntax or terminal commands — conceptual direction only.

#### 4. Remediation Plan
- Provide exactly 4 remediation items ordered by priority: \
most critical first.
- Each item MUST follow this exact structure:
  **Issue**: [Specific injection type or configuration risk this addresses]
  **Action**: [Plain step-by-step — what needs to happen, who needs \
to do it, in language a non-technical person can follow or hand off]
  **Benefit**: [One sentence — what risk does this eliminate?]
  **Owner**: [Dev Team / DBA / IT Support / Both]
  **Timeline**: [Critical — Immediate / High — This Sprint / Medium — This Quarter / Low — When Possible]
- Do NOT include code snippets, prepared statement syntax, \
or terminal commands.

#### 5. Risk Score Breakdown

Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Injection Risk
2. Privilege Exposure
3. Data Exposure
4. Attack Complexity

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Determine the correct path from [SCAN DATA] using this logic:
- Database Status is 'Exposed' OR Privilege Flag indicates CRITICAL → Critical path
- Database Status is not 'Exposed' but vulnerabilities exist → At Risk path
- No vulnerabilities found → Secure path
Mark the correct path with [ YOU ARE HERE ]. Leave others unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your database is actively exposed and potentially already compromised.

→ Step 1: [Most urgent action — specific to the highest severity finding and privilege level]
→ Step 2: [Second action — specific to scan findings]
→ Step 3: [Who to escalate to and what to tell them]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SQL injection vulnerabilities were found but the database is not \
yet confirmed as fully exposed.

→ Step 1: [Most urgent fix from the vulnerability findings]
→ Step 2: [Second action — input validation or privilege reduction]
→ Step 3: [Recommended follow-up scan or verification step]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No SQL injection vulnerabilities were detected. Focus on maintaining \
your secure coding practices.

→ Step 1: [Proactive measure — e.g., schedule regular re-scans]
→ Step 2: [One hardening recommendation based on the fingerprint data]
→ Step 3: [Long-term best practice for database security]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must reference actual findings from [SCAN DATA] — not generic boilerplate.
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed — do not alter them.
- Path determination logic is fixed as defined above — do not override it.

================================================================================
[SCAN DATA]
================================================================================
Target URL         : {target_url}
Scan Date          : {scan_date}
ML Threat Index    : {ml_threat_index}
Database Status    : {db_status}
Total Vulns Found  : {vuln_count}
Injection Types    : {injection_types}
Scan Coverage      : {scan_coverage}
Scan Limitations   : {scan_limitations}

### Database Fingerprint:
- Technology   : {detected_dbms}
- Version      : {db_version}
- Current User : {current_user}
- Current DB   : {current_database}
- Privilege Flag: {privilege_flag}

{vuln_block}
================================================================================
[END OF SCAN DATA]
================================================================================
"""
    return prompt


def _format_killchain_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze NetShieldAI Kill Chain audit data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Kill Chain narrative threading across all phases (Recon → Weaponization → Exploitation)
      - Enforced per-finding structure with attacker narratives and business impact scoring
      - Priority-sorted vulnerabilities: CRITICAL → HIGH → MEDIUM in Python before injection
      - Structured Markdown phase assessment + Risk Score Breakdown (Section 5)
      - Decision Guide (Section 6)
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Core Data ---
    meta   = parsed_data.get("metadata", {})
    risks  = parsed_data.get("risk_summary", {})
    phases = parsed_data.get("phase_analysis", {})
    recon  = phases.get("recon", {})
    tech   = phases.get("weaponization", {})
    vulns  = parsed_data.get("vulnerabilities", [])

    target    = meta.get("target", "Unknown")
    scan_date = meta.get("scan_date", "Unknown")
    profile   = meta.get("profile", "Full Audit")
    aggression = meta.get("aggression", "N/A")

    critical_count = risks.get("critical", 0)
    high_count     = risks.get("high", 0)
    medium_count   = risks.get("medium", 0)
    total_count    = risks.get("total", 0)

    # Phase 1: Recon
    recon_ip        = recon.get("target_ip", "Unknown")
    subdomains_count = recon.get("subdomains_count", 0)
    server_tech     = recon.get("server", "Unknown")

    # Phase 2: Network
    net_audit   = phases.get("network_audit", {})
    net_status  = net_audit.get("status", "Unknown")
    os_finger   = net_audit.get("os", "N/A")
    open_ports  = net_audit.get("open_ports", [])

    # Phase 3: Web
    web_audit   = phases.get("web_audit", {})
    waf_status  = web_audit.get("waf", "None Detected")
    surface_area = web_audit.get("surface", "N/A")

    # Phase 4: Traffic
    traffic_audit = phases.get("traffic_audit", {})
    packets_captured = traffic_audit.get("packets", 0)

    # --- 2. Priority-Sort Vulnerabilities: CRITICAL → HIGH → MEDIUM → LOW ---
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_vulns = sorted(
        vulns,
        key=lambda v: severity_order.get(v.get("severity", "").upper(), 99)
    )

    # Top priorities for injection (cap at 10 to avoid token overflow)
    top_vulns = sorted_vulns[:10]

    # --- 3. Determine Kill Chain Breach Depth ---
    has_recon         = bool(open_ports or subdomains_count > 0)
    has_exploitation  = any(
        v.get("severity", "").upper() in ["CRITICAL", "HIGH"]
        for v in vulns
    )
    has_critical      = critical_count > 0

    if has_critical:
        breach_depth = "FULL COMPROMISE RISK"
    elif has_exploitation:
        breach_depth = "EXPLOITATION POSSIBLE"
    elif has_recon:
        breach_depth = "RECONNAISSANCE COMPLETE"
    else:
        breach_depth = "MINIMAL EXPOSURE"
        
    recon_status_str = "Complete" if has_recon else "Incomplete"

    # --- 4. Build Phase Blocks ---
    phase_data = [
        "### Phase 1 — Reconnaissance & Discovery:",
        f"- Target IP      : {recon_ip}",
        f"- Subdomains Found: {subdomains_count}",
        f"- Technology Stack: {server_tech}",
        "",
        "### Phase 2 — Network Audit:",
        f"- Host Status     : {net_status}",
        f"- OS Fingerprint  : {os_finger}",
        f"- Open Ports Discovered: {', '.join(open_ports) if open_ports else 'None'}",
        "",
        "### Phase 3 — Web Application Audit:",
        f"- WAF Status      : {waf_status}",
        f"- Attack Surface  : {surface_area}",
        "",
        "### Phase 4 — Traffic Analysis:",
        f"- Packet Intelligence: {packets_captured} packets captured during audit"
    ]
    phased_block = "\n".join(phase_data)

    # --- 5. Build Vulnerabilities Block ---
    if top_vulns:
        vuln_lines = ["### Aggregated Security Findings (Pre-Sorted by Severity):"]
        for i, v in enumerate(top_vulns, 1):
            vuln_lines.append(f"--- FINDING #{i} ---")
            vuln_lines.append(f"Title      : {v.get('title', 'N/A')}")
            vuln_lines.append(f"Severity   : {v.get('severity', 'N/A')}")
            vuln_lines.append(f"CWE        : {v.get('cwe', 'N/A')}")
            vuln_lines.append(f"ML Score   : {v.get('ml_threat_score', 'N/A')}/10.0")
            vuln_lines.append(f"Context    : {v.get('description', 'N/A')[:250]}...")
            vuln_lines.append(f"Fix        : {v.get('remediation', 'N/A')}\n")
        vuln_block = "\n".join(vuln_lines)
    else:
        vuln_block = (
            "### Aggregated Security Findings:\n"
            "No vulnerabilities detected."
        )

    # --- 6. Build Scan Coverage Disclaimer ---
    scan_coverage = (
        "External reconnaissance (open ports, subdomains, URLs), "
        "technology fingerprinting, and automated vulnerability detection "
        "across discovered endpoints"
    )
    scan_limitations = (
        "Full manual penetration testing, authenticated user flows, "
        "internal network segments, physical security assessments, or "
        "social engineering attack vectors"
    )

    # --- 7. Build Open Ports Summary ---
    ports_summary = (
        ", ".join(open_ports) if open_ports else "None detected"
    )

    # --- 8. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Lead Penetration Tester and Strategic Security Advisor** — \
an expert at translating complex, multi-phase security audit findings into clear, \
actionable intelligence for business owners and executive stakeholders, not just \
technical teams.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the Kill Chain Assessment data provided in the [SCAN DATA] block below \
and produce a professional "Full-Spectrum Kill Chain Security Briefing" report \
in exactly 6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "Kill Chain (the step-by-step journey an attacker takes — from \
first discovering your website exists, to fully compromising it — this report \
maps every step of that journey for your specific target)"
  Example: "Reconnaissance (the intelligence-gathering phase — like a burglar \
walking past your house, noting which windows are open, where the cameras are, \
and when you leave for work — before ever attempting to break in)"
  Example: "Weaponization (the preparation phase — once the attacker knows \
your technology stack, they select or build the specific tools designed to \
exploit your exact setup)"
  Example: "Attack Surface (the total number of ways an attacker could \
potentially get in — every open port, every subdomain, every public-facing \
URL is a door that needs to be assessed)"
  Example: "CWE (Common Weakness Enumeration — a standardised catalogue \
number that security professionals use to classify types of vulnerabilities, \
like a library reference number for software flaws)"
- This report covers multiple phases of a simulated attack — always frame \
findings in terms of the attacker's journey, not as isolated technical issues.
- Write for two audiences simultaneously:
  • Business Owner / Executive: Needs to understand the STRATEGIC RISK \
and BUSINESS IMPACT of the full attack chain.
  • Developer / IT Team: Needs TECHNICAL CONTEXT per phase and \
SPECIFIC FIX DIRECTION.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [SCAN DATA] block. Do not invent ports, \
subdomains, technologies, or vulnerabilities not present in the data.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  The Kill Chain narrative MUST thread through Sections 1–4 — each phase \
section must reference how its findings ENABLE the next phase. The report \
must read as a connected story, not isolated technical sections.
5.  Vulnerability order in Section 4 MUST follow: \
CRITICAL → HIGH → MEDIUM → LOW. The data block is pre-sorted — \
maintain that order.
6.  Every finding in Section 4 (Part B) MUST follow the exact four-part \
structure defined in Section 4 instructions — no exceptions.
7.  The attacker scenario in Section 4 (part c) MUST be written as a \
narrative short story — do NOT use abstract language like \
"could be exploited" or "may allow unauthorized access." \
The scenario MUST reference the specific recon data (ports, subdomains) \
and tech stack from [SCAN DATA] to show how earlier phases enabled this exploit.
8.  Every remediation item (Section 4, Part C) MUST follow \
the exact structure with Owner and Timeline tags — no code snippets.
9.  The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 paths: Critical / At Risk / Secure.
    b. Use this path determination logic:
       - ANY Critical vulnerability OR Breach Depth is 'FULL COMPROMISE RISK' \
→ Critical path
       - No Critical but High exists OR Breach Depth is 'EXPLOITATION POSSIBLE' \
→ At Risk path
       - Neither → Secure path
    c. Mark the matching path with [ YOU ARE HERE ].
    d. Always show all 3 paths — never omit one.
10. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
11. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Kill Chain Summary

Before the verdict paragraph, produce a Markdown metadata table with
exactly these two columns:
| Field | Value |
|---|---|
| Report Generated By | NetShieldAI Kill Chain Assessment |
| Scan Target | {target} |
| Scan Date | {scan_date} |
| Audit Profile | {profile} |
| Breach Depth | {breach_depth} |
| Reconnaissance Status | {recon_status_str} |
| Target IP | {recon_ip} |
| Server Tech | {server_tech} |
| Host Status | {net_status} |
| WAF Status | {waf_status} |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

**Attack Chain Narrative**
Write exactly 2 sentences describing the most dangerous end-to-end attack \
path evidenced by the scan data (started from recon, to tech stack, to compromise).

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | [Secure / At Risk / Critical] | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | {total_count} | One sentence on whether this volume is typical or elevated
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|

Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. Phase 1 — Reconnaissance & Exposure
- Open with a plain-English explanation of what the Reconnaissance phase \
represents in an attack — what is the attacker doing and why does it matter \
that they can do it? (2 sentences maximum, use the Kill Chain analogy \
from the ROLE block)
- Analyze the open ports found:
  For each port, state in plain English what service it exposes and \
whether that exposure is expected or concerning for this type of target.
- Assess the subdomain and URL discovery:
  Give a plain-English verdict on whether the discovered attack surface \
(subdomains + URLs) is typical, elevated, or excessive for a site of this type.
- End this section with a Phase Link sentence:
  "With this reconnaissance data in hand, an attacker now knows [X] — \
which directly enables the next phase: [plain-English description of \
how recon findings feed into weaponization]."

#### 3. Phase 2 — Weaponization & Tech Stack Risk
- Open with a plain-English explanation of what Weaponization means \
in the Kill Chain context — the attacker is no longer just watching, \
they are now preparing. (2 sentences maximum)
- For each technology detected in [SCAN DATA], produce a plain-English \
assessment:
  a. What is this technology and what does it do?
  b. What does knowing the specific version give an attacker?
  c. Is this version current, outdated, or end-of-life?
- End this section with a Phase Link sentence:
  "Armed with knowledge of [specific tech stack details], an attacker \
can now select purpose-built tools targeting these exact versions — \
moving directly into the exploitation phase."

#### 4. Phase 3 — Exploitation & Critical Findings

**Part A — Exploitation Summary Table**
Produce a Markdown table with exactly these five columns:
| # | Severity | Vulnerability | What This Enables | Priority |
|---|---|---|---|---|

Column guidance:
- **Vulnerability**: Plain-English name with technical name in parentheses.
- **What This Enables**: One sentence — what can the attacker DO if \
they exploit this? Written as a capability, not an abstract risk.
  Example: "Read and delete all database records" not "data exposure risk"
- **Priority**: Critical — Fix Now / High — Fix Soon / Medium — Monitor / Low — No Action Needed

**Part B — Deep Dive Per Finding**
For each finding in [SCAN DATA], follow this EXACT four-part structure:

**Finding #[N] — [Title] | CRITICAL / HIGH / MEDIUM**

**a. Plain-English Explanation**
What is this vulnerability? 2–3 sentences for a non-technical reader. \
Always reference which phase of the Kill Chain this finding belongs to \
and how the earlier recon or weaponization data made it discoverable.

**b. Business Impact Assessment**
Produce a Markdown table with exactly these two columns:
| Impact Dimension | Rating |
|---|---|
| Financial | Low / Medium / High |
| Data Risk | Low / Medium / High |
| Reputation | Low / Medium / High |

Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose? Reference the actual target \
and tech stack from [SCAN DATA].

**c. Kill Chain Attacker Scenario**
Write a concrete narrative (4–6 sentences) that starts from the \
Reconnaissance phase and walks through to exploitation of THIS specific \
vulnerability. The scenario MUST:
- Reference the specific ports/subdomains discovered in Phase 1.
- Reference the specific technology version from Phase 2.
- End with what the attacker achieves — specific to the finding's severity \
and the target's context.
Do NOT use abstract language. Write it as a story.

**d. Fix Direction**
- What needs to change — in plain English, no code syntax.
- Why this fix works, explained so a non-developer understands.
- One sentence on which team owns this fix.

**Part C — Remediation Plan**
Provide exactly 4 remediation items ordered by priority: most critical first.
Each item MUST follow this exact structure:
  **Issue**: [Specific finding or phase risk this addresses]
  **Action**: [Plain step-by-step — no commands or code]
  **Benefit**: [What risk does this eliminate?]
  **Owner**: [Dev Team / IT Support / Both / Management]
  **Timeline**: [Critical — Immediate / High — This Sprint / Medium — This Quarter / Low — When Possible]

#### 5. Kill Chain Visuals

**Part A — Kill Chain Phase Assessment**

Produce a Markdown table assessing attacker progression through each kill
chain phase based strictly on the scan data.

Produce a Markdown table with exactly these four columns:
| Phase | Status | Evidence from Scan Data | Risk Implication |
|---|---|---|---|

Phases to assess (in order):
1. Phase 1 — Reconnaissance
2. Phase 2 — Weaponization
3. Phase 3 — Exploitation
4. Phase 4 — Full Compromise

Rules for the Phase Assessment table:
- Status must be exactly one of: REACHABLE / BLOCKED / UNCONFIRMED
- Evidence from Scan Data must reference specific values from the scan
  data block — port counts, subdomain counts, finding severities, or
  technology names. Do not write generic descriptions.
- Risk Implication must be one plain-English sentence on what the
  attacker gains or cannot gain at this phase based on the evidence.

After the table, produce a two-column summary table:
| Breach Depth Assessment | Attacker Reach |
|---|---|

- Breach Depth Assessment must reproduce the pre-computed Breach Depth
  value from the scan data verbatim.
- Attacker Reach must be one plain-English sentence describing how far
  an attacker can realistically progress given the evidence.

**Part B — Risk Score Breakdown**

Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Recon Exposure
2. Tech Stack Risk
3. Exploit Severity
4. Attack Surface

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Determine the correct path from [SCAN DATA] using this logic:
- ANY Critical vulnerability OR Breach Depth = 'FULL COMPROMISE RISK' \
→ Critical path
- No Critical but High exists OR Breach Depth = 'EXPLOITATION POSSIBLE' \
→ At Risk path
- Neither condition met → Secure path
Mark the matching path [ YOU ARE HERE ]. Leave others unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
An attacker has everything they need to fully compromise this target. \
Immediate action is required.

→ Step 1: [Most urgent action — specific to highest severity finding \
and breach depth]
→ Step 2: [Second action — address the most exposed recon surface]
→ Step 3: [Who to escalate to and what to tell them — plain English]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The attacker has progressed through reconnaissance and weaponization \
but full exploitation has not been confirmed.

→ Step 1: [Address the highest-risk exploitation finding]
→ Step 2: [Reduce the recon surface — specific to ports/subdomains found]
→ Step 3: [Recommended follow-up — manual pen test or re-scan]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No critical exploitation paths were identified. Focus on reducing \
the recon surface and hardening the tech stack.

→ Step 1: [Reduce unnecessary open ports or subdomains if any found]
→ Step 2: [Proactive tech stack hardening recommendation]
→ Step 3: [Schedule regular Kill Chain re-assessments]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must reference actual findings from [SCAN DATA].
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed — do not alter them.
- Path logic is fixed as defined above — do not override it.

================================================================================
[SCAN DATA]
================================================================================
Target             : {target}
Scan Date          : {scan_date}
Audit Profile      : {profile}
Aggression         : {aggression}
Threat Resilience  : {breach_depth}

### Risk Dashboard:
- Critical Findings : {critical_count}
- High Findings     : {high_count}
- Medium Findings   : {medium_count}
- Total Items       : {total_count}

{phased_block}

{tech_block}

{vuln_block}

### Breach Depth Assessment (Pre-Computed):
- Breach Depth      : {breach_depth}
- Recon Complete    : {"Yes" if has_recon else "No"}
- Exploitation Found: {"Yes" if has_exploitation else "No"}
- Critical Confirmed: {"Yes" if has_critical else "No"}
================================================================================
[END OF SCAN DATA]
================================================================================
"""
    return prompt

def _format_api_scan_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze NetShieldAI API Scanner data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - HTTP method risk flags built in Python before injection
      - TCTR score interpretation with threshold-based urgency labels
      - Enforced per-finding structure with attacker narratives and business impact scoring
      - Priority-sorted findings: CRITICAL → HIGH → MEDIUM → LOW in Python
      - Owner-tagged, timeline-aware remediation (no code snippets)
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Core Data ---
    meta = parsed_data.get("metadata", {})
    summary = parsed_data.get("summary", {})
    findings = parsed_data.get("findings", [])
    target_url = meta.get("target_url", "N/A")
    scan_date = meta.get("scan_date", "N/A")

    high_count   = summary.get("High", 0)
    medium_count = summary.get("Medium", 0)
    low_count    = summary.get("Low", 0)
    total_count  = summary.get("Total", 0)
    
    audited = summary.get("audited", "Unknown")
    critical_endpoints = summary.get("critical_endpoints", "Unknown")

    # --- 2. Priority-Sort Findings: CRITICAL → HIGH → MEDIUM → LOW ---
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(
            (f.get("risk_level", "")).upper(), 99
        )
    )
    # Cap at 15 to avoid token overflow
    top_findings = sorted_findings[:15]

    # --- 3. HTTP Method Risk Flag Builder ---
    METHOD_RISK = {
        "DELETE" : ("High Risk",   "permanently removes data — if unprotected, "
                                   "an attacker can destroy records"),
        "PUT"    : ("High Risk",   "overwrites existing data — if unprotected, "
                                   "an attacker can modify any record"),
        "PATCH"  : ("Medium Risk", "partially updates data — if unprotected, "
                                   "an attacker can alter specific fields"),
        "POST"   : ("Medium Risk", "creates new data or triggers actions — "
                                   "if unprotected, an attacker can inject records"),
        "GET"    : ("Low Risk",    "retrieves data — if unprotected, "
                                   "an attacker can read sensitive information"),
        "OPTIONS": ("Low Risk",    "reveals what methods an endpoint supports — "
                                   "useful intelligence for an attacker"),
    }

    def get_method_flag(method: str) -> str:
        method_upper = method.upper()
        if method_upper in METHOD_RISK:
            level, reason = METHOD_RISK[method_upper]
            return f"{level} — {method_upper} {reason}"
        return f"Unknown Method — review manually"

    # Identify Highest Risk HTTP Method dynamically
    methods_found = [f.get("method", "GET").upper() for f in findings]
    highest_risk_method = "None"
    for m in ["DELETE", "PUT", "PATCH", "POST", "GET", "OPTIONS"]:
        if m in methods_found:
            highest_risk_method = m
            break

    # --- 4. TCTR Score Interpreter ---
    def interpret_tctr_magnitude(magnitude: str) -> str:
        try:
            val = float(magnitude.replace('%', ''))
            if val >= 80:
                return "Critical — immediate remediation required"
            elif val >= 60:
                return "High — address this sprint"
            elif val >= 30:
                return "Medium — address this quarter"
            else:
                return "Low — monitor and review"
        except (ValueError, TypeError):
            return "Unscored — manual review recommended"

    # --- 5. Build Findings Block ---
    if top_findings:
        finding_lines = ["### API Endpoint Findings (Pre-Sorted by Severity):"]
        for i, f in enumerate(top_findings, 1):
            method      = f.get("method", "GET")
            risk        = f.get("risk_level", "N/A")
            tctr        = f.get("tctr_magnitude", "N/A")
            priority    = f.get("priority", "N/A")
            description = f.get("description", "N/A")
            ai_breakdown = f.get("ai_breakdown", "N/A")

            finding_lines.append(f"--- FINDING #{i} ---")
            finding_lines.append(f"Name            : {f.get('name', 'N/A')}")
            finding_lines.append(f"Risk Level      : {risk}")
            finding_lines.append(f"Priority        : {priority}")
            finding_lines.append(f"Endpoint        : [{method}] {f.get('url', 'N/A')}")
            finding_lines.append(f"Method Risk Flag: {get_method_flag(method)}")
            finding_lines.append(f"TCTR Magnitude  : {tctr} → {interpret_tctr_magnitude(tctr)}")
            finding_lines.append(f"AI Breakdown    : {ai_breakdown}")
            finding_lines.append(f"CWE Mapping     : {f.get('cwe', 'N/A')}")
            finding_lines.append(f"Technical Meta  : {description[:500]}...\n")
        findings_block = "\n".join(finding_lines)
    else:
        findings_block = "### API Endpoint Findings:\nNo findings detected."

    # --- 6. Build Scan Coverage & Limitations ---
    scan_coverage = (
        "Publicly accessible API endpoints, HTTP method handling, authentication "
        "header presence, and known vulnerability signatures detectable via automated scanning"
    )
    scan_limitations = (
        "Authenticated endpoints requiring valid session tokens (unless authenticated "
        "scanning was configured), internal microservices or private API routes, "
        "business logic flaws, and API gateway or rate-limiting configurations beyond "
        "what is detectable externally"
    )

    # --- 7. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior API Security Consultant** — an expert at making \
complex API vulnerability findings clear and actionable for both business owners \
and development teams, not just security professionals.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the API Scanner data provided in the [SCAN DATA] block below and produce \
a professional "API Security Briefing" report in exactly 6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "API — Application Programming Interface (the behind-the-scenes \
channel that allows your website, mobile app, or software to send and receive \
data — think of it as a waiter taking orders between your app and your database)"
  Example: "REST API Endpoint (a specific URL address that your application \
calls to perform an action — like /api/users/delete is the address for \
deleting a user account)"
  Example: "HTTP Method (the type of action being requested — GET means \
read, POST means create, PUT/PATCH means update, DELETE means destroy)"
  Example: "Authentication Header (a digital pass that proves the caller \
has permission to use this endpoint — like a staff badge for your API)"
  Example: "TCTR Score (NetShieldAI's combined threat-to-risk rating — \
a score from 0–10 where higher means more urgent attention is needed)"
  Example: "IDOR — Insecure Direct Object Reference (a flaw where an attacker \
changes a number in a URL to access someone else's data — like changing \
/api/orders/1001 to /api/orders/1002 to read another customer's order)"
  Example: "Rate Limiting (a control that prevents any single caller from \
making too many requests too quickly — without it, attackers can bombard \
your API or scrape all your data)"
- Write for two audiences simultaneously:
  • Business Owner: Needs to understand DATA EXPOSURE RISK and BUSINESS IMPACT.
  • Developer: Needs TECHNICAL CONTEXT per endpoint and SPECIFIC FIX DIRECTION.
  Serve both in every finding.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [SCAN DATA] block. Do not invent \
endpoints, methods, or vulnerabilities not present in the data.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  Findings in Section 2 MUST follow the order: \
CRITICAL → HIGH → MEDIUM → LOW → INFO. \
The data block is pre-sorted — maintain that order.
5.  Every finding in Section 2 (Part B) MUST follow the exact four-part \
structure defined in Section 2 instructions — no exceptions.
6.  The attacker scenario in Section 2 (part c) MUST:
    a. Reference the specific endpoint URL and HTTP method from [SCAN DATA].
    b. Be written as a concrete narrative short story — do NOT use abstract \
language like "could allow unauthorized access."
    c. Explicitly use the Method Risk Flag from [SCAN DATA] to frame the \
severity of what the attacker can do with that specific method.
7.  The TCTR Score for each finding MUST be interpreted using the \
pre-computed label from [SCAN DATA] — do not re-score or override it.
8.  Section 3 (API Hardening Guidance) MUST be specific to the actual \
endpoints and findings in [SCAN DATA] — not generic REST best practices.
9.  Every remediation item in Section 4 MUST follow the exact structure \
with Owner and Timeline tags — no code snippets or terminal commands.
10. Remediation items in Section 4 MUST be ordered by priority: \
most critical first.
11. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 paths: Critical / At Risk / Secure.
    b. Use this path determination logic:
       - ANY High or Critical finding → Critical path
       - No High/Critical but Medium findings exist → At Risk path
       - No findings above Low/Info → Secure path
    c. Mark the matching path with [ YOU ARE HERE ].
    d. Always show all 3 paths — never omit one.
12. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
13. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary

Before the verdict paragraph, produce a Markdown metadata table with
exactly these two columns:
| Field | Value |
|---|---|
| Report Generated By | NetShieldAI API Security Audit |
| API Base URL | {target_url} |
| Audit Date | {scan_date} |
| Endpoints Audited | {audited} |
| Critical / High Vulnerabilities | {high_count} |
| Highest Risk HTTP Method | {highest_risk_method} |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

**API Risk Context**
Add one sentence classifying the API as consumer, internal, or indeterminate \
based on the endpoints and data patterns detected.

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | [Secure / At Risk / Critical] | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | {total_count} | One sentence on whether this volume is typical or elevated
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|

Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. API Endpoint Vulnerability Analysis

**Part A — Endpoint Risk Summary Table**
Produce a Markdown table with exactly these six columns:
| # | Risk | Endpoint | HTTP Method | Method Risk | TCTR Score |
|---|---|---|---|---|---|

Column guidance:
- **Endpoint**: The URL path from [SCAN DATA].
- **HTTP Method**: GET / POST / PUT / PATCH / DELETE / OPTIONS
- **Method Risk**: Reproduce the Method Risk Flag from [SCAN DATA] \
verbatim for this finding.
- **TCTR Score**: Reproduce the pre-computed TCTR label from [SCAN DATA] \
verbatim — do not re-score.

**Part B — Deep Dive Per Finding**
For each finding in [SCAN DATA], follow this EXACT four-part structure:

**Finding #[N] — [Name] | CRITICAL / HIGH / MEDIUM / LOW**
**Endpoint**: `[METHOD] /path/to/endpoint`
**TCTR**: [score] → [pre-computed label from SCAN DATA]

**a. Plain-English Explanation**
What is this vulnerability? 2–3 sentences for a non-technical reader. \
Explain what this specific endpoint does in plain English before \
explaining what is wrong with it. Use the jargon examples from the \
ROLE block as a model.

**b. Business Impact Assessment**
Produce a Markdown table with exactly these two columns:
| Impact Dimension | Rating |
|---|---|
| Financial | Low / Medium / High |
| Data Risk | Low / Medium / High |
| Reputation | Low / Medium / High |

Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose? Reference the actual endpoint \
and method from [SCAN DATA].

**c. Attacker Scenario**
Write a concrete narrative (3–5 sentences). Reference the specific \
endpoint URL and HTTP method. Use the Method Risk Flag to frame \
what the attacker can destroy, read, or modify. Do NOT use abstract \
language — write it as a story the business owner can picture.
Example: "An attacker discovers your [DELETE] /api/users/{{id}} endpoint \
is publicly accessible without requiring a login. They write a simple \
script that calls this endpoint with incrementing user ID numbers. \
Within minutes, they have deleted every user account in your system — \
taking your application completely offline and destroying years of \
customer data."

**d. Fix Direction**
- What specifically needs to change on this endpoint — plain English.
- Why this fix works, explained so a non-developer understands.
- Reference the specific endpoint from [SCAN DATA].
- No code syntax or terminal commands.

#### 3. API Hardening Guidance
This section replaces generic best practices with finding-specific \
hardening recommendations derived from the actual endpoints in [SCAN DATA].

- For each unique vulnerability pattern found across the findings \
(e.g., missing authentication, unprotected DELETE methods, missing \
rate limiting), write one hardening recommendation.
- Each recommendation MUST:
  a. Name the specific pattern it addresses.
  b. Reference at least one actual endpoint from [SCAN DATA] as an example.
  c. Explain in plain English what the hardening achieves and why \
it matters for this specific API.
- Do NOT write generic REST security advice that could apply to any API.

#### 4. Prioritized Remediation Checklist
Provide exactly 4 remediation items ordered by priority: most critical first.
Each item MUST follow this exact structure:
  **Issue**: [Specific endpoint and vulnerability this addresses]
  **Action**: [Plain step-by-step — no code or terminal commands]
  **Benefit**: [One sentence — what risk does this eliminate?]
  **Owner**: [Dev Team / IT Support / Both]
  **Timeline**: [Critical — Immediate / High — This Sprint / Medium — This Quarter / Low — When Possible]

After the 4 items, write one sentence summarising the overall \
remediation effort — is this a quick afternoon of fixes or a \
multi-sprint hardening project?

#### 5. Risk Score Breakdown

Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Authentication
2. Endpoint Exposure
3. Injection Risk
4. Method Control

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Determine the correct path from [SCAN DATA] using this logic:
- ANY High or Critical finding present → Critical path
- No High/Critical but Medium findings exist → At Risk path
- No findings above Low/Info → Secure path
Mark the correct path with [ YOU ARE HERE ]. Leave others unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your API has serious vulnerabilities that expose your data and \
business logic to attackers right now.

→ Step 1: [Most urgent action — specific to highest severity \
finding and its endpoint]
→ Step 2: [Second action — address next highest risk endpoint]
→ Step 3: [Who to escalate to and what to tell them]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Medium-severity issues were found that should be addressed before \
they are discovered and escalated by an attacker.

→ Step 1: [Most urgent medium-risk endpoint fix]
→ Step 2: [Second action — hardening or access control improvement]
→ Step 3: [Recommended follow-up scan or penetration test]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No significant vulnerabilities detected. Focus on maintaining \
strong API security practices.

→ Step 1: [Address any Low/Info findings as quick wins]
→ Step 2: [One proactive hardening tip based on the endpoint data]
→ Step 3: [Schedule regular API re-scans]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must reference actual endpoints from [SCAN DATA].
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed — do not alter them.
- Path determination logic is fixed as defined above.

================================================================================
[SCAN DATA]
================================================================================
Target URL         : {target_url}
Scan Date          : {scan_date}
Endpoints Audited  : {audited}
Critical Endpoints : {critical_endpoints}

### Risk Summary:
- Critical Findings : {high_count}
- Medium Findings   : {medium_count}
- Low / Info Findings: {low_count}
- Total Findings    : {total_count}

{findings_block}
================================================================================
[END OF SCAN DATA]
================================================================================
"""
    return prompt

def _format_semgrep_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze NetShieldAI Semgrep SAST data.
    Optimized for:
      - High-quality, consistent LLM output
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Priority-sorted findings: ERROR → WARNING → INFO in Python before injection
      - False positive caveat built in Python and explicitly called out
      - Enforced per-finding structure with attacker narratives and business impact scoring
      - Owner-tagged, timeline-aware remediation (no code snippets)
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Core Data ---
    meta     = parsed_data.get("scan_metadata", {})
    summary  = parsed_data.get("summary_counts", {})
    findings = parsed_data.get("findings", [])

    tool          = meta.get("tool", "Semgrep SAST")
    scan_target   = meta.get("scan_target", meta.get("target", "N/A"))
    scan_date     = meta.get("scan_date", "N/A")
    language      = meta.get("language", meta.get("languages", "N/A"))
    files_scanned = meta.get("files_scanned", meta.get("file_count", "N/A"))
    framework     = meta.get("framework", "N/A")

    total_count   = summary.get("Total", 0)
    error_count   = summary.get("Error", 0)
    warning_count = summary.get("Warning", 0)
    info_count    = summary.get("Info", summary.get("Information", 0))

    # --- 2. Priority-Sort Findings: ERROR → WARNING → INFO ---
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2, "INFORMATION": 2}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "").upper(), 99)
    )
    # Cap at 15 to avoid token overflow
    top_findings = sorted_findings[:15]

    # --- 3. Rule ID Plain-English Classifier ---
    # Maps common Semgrep rule namespace prefixes to plain-English vulnerability categories
    RULE_CATEGORY_MAP = {
        "injection"        : "Code Injection",
        "sql"              : "SQL Injection",
        "xss"              : "Cross-Site Scripting",
        "ssrf"             : "Server-Side Request Forgery",
        "path-traversal"   : "Path Traversal",
        "traversal"        : "Path Traversal",
        "crypto"           : "Weak Cryptography",
        "taint"            : "Tainted Data Flow",
        "secret"           : "Hardcoded Secret / Credential",
        "hardcoded"        : "Hardcoded Secret / Credential",
        "auth"             : "Authentication Weakness",
        "deserialization"  : "Insecure Deserialization",
        "xxe"              : "XML External Entity (XXE) Injection",
        "redirect"         : "Open Redirect",
        "cors"             : "Misconfigured CORS Policy",
        "header"           : "Missing Security Header",
        "csrf"             : "Cross-Site Request Forgery (CSRF)",
        "race"             : "Race Condition",
        "overflow"         : "Buffer Overflow",
        "log"              : "Log Injection",
        "format"           : "Format String Vulnerability",
        "command"          : "OS Command Injection",
        "ldap"             : "LDAP Injection",
        "xpath"            : "XPath Injection",
    }

    def classify_rule(rule_id: str) -> str:
        """Returns a plain-English category for a Semgrep rule ID."""
        rule_lower = rule_id.lower()
        for keyword, category in RULE_CATEGORY_MAP.items():
            if keyword in rule_lower:
                return category
        return "Security Misconfiguration"

    # --- 4. Build Findings Block ---
    if top_findings:
        finding_lines = ["### SAST Findings (Pre-Sorted by Severity):"]
        for i, f in enumerate(top_findings, 1):
            rule_id      = f.get("rule", "N/A")
            severity     = f.get("severity", "N/A")
            file_loc     = f.get("file", "N/A")
            line_no      = f.get("line", "N/A")
            description  = f.get("description", "N/A")
            suggested    = f.get("suggested_fix", "N/A")
            category     = classify_rule(rule_id)

            finding_lines.append(f"--- FINDING #{i} ---")
            finding_lines.append(f"Rule ID          : {rule_id}")
            finding_lines.append(f"Vulnerability    : {category}")
            finding_lines.append(f"Severity         : {severity}")
            finding_lines.append(f"Location         : {file_loc} — Line {line_no}")
            finding_lines.append(f"Description      : {description}")
            finding_lines.append(f"Vulnerable Code  : {f.get('vulnerable_code', 'N/A')}")
            finding_lines.append(f"Suggested Fix    : {suggested}\n")
        findings_block = "\n".join(finding_lines)
    else:
        findings_block = "### SAST Findings:\nNo findings detected."

    # --- 5. Compute False Positive Context ---
    if total_count > 0:
        estimated_fp_low  = max(1, round(total_count * 0.20))
        estimated_fp_high = max(1, round(total_count * 0.40))
        false_positive_note = (
            f"Semgrep SAST tools typically flag 20–40% of findings as false positives "
            f"upon manual review. For this scan's {total_count} total findings, "
            f"approximately {estimated_fp_low}–{estimated_fp_high} findings may require "
            f"manual verification before acting. This does NOT mean findings should be "
            f"ignored — it means each finding should be confirmed by a developer before "
            f"remediation effort is assigned."
        )
    else:
        false_positive_note = (
            "No findings were detected. This may indicate a clean codebase or that the "
            "scan scope did not cover all relevant files — verify scan coverage before "
            "treating this as a full clean bill of health."
        )

    # --- 6. Build Scan Coverage & Limitations ---
    scan_coverage = (
        "Static code patterns, known vulnerability signatures, tainted data flows, "
        "and hardcoded secrets detectable via automated rule matching"
    )
    scan_limitations = (
        "Executing the code, runtime behaviour testing, deployed infrastructure assessment, "
        "live environment authentication flows, or vulnerabilities that only manifest under "
        "specific runtime conditions"
    )

    # --- 7. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior Secure Code Reviewer** — an expert at making \
complex static code analysis findings clear and actionable for both business \
owners and development teams, not just security engineers.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the Semgrep SAST data provided in the [SCAN DATA] block below and \
produce a professional "Secure Code Review Briefing" report in exactly 6 sections.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "SAST — Static Application Security Testing (a method of scanning \
your application's source code without running it — like a grammar checker \
for security flaws, reading every line of code looking for dangerous patterns)"
  Example: "Tainted Data Flow (when data from an untrusted source — like a \
user's input — travels through your code and reaches a sensitive operation \
like a database query without being cleaned first)"
  Example: "Hardcoded Secret (a password, API key, or encryption key that has \
been typed directly into the source code — like writing your house key's \
combination on the outside of the door)"
  Example: "Path Traversal (a technique where an attacker manipulates a file \
path in your application to access files outside the intended directory — \
like typing '../../etc/passwd' to navigate up and read the server's \
password file)"
  Example: "Semgrep Rule ID (the internal reference code for the specific \
security pattern that was matched — like a catalogue number for the type \
of flaw detected)"
  Example: "ERROR severity (the highest Semgrep alert level — these are \
definite or near-definite security flaws that require immediate attention)"
  Example: "WARNING severity (probable security issues that are likely \
real flaws but may need developer verification before acting)"
- Write for two audiences simultaneously:
  • Business Owner: Needs to understand RISK, DATA EXPOSURE, and \
BUSINESS IMPACT — not which file or line the flaw is on.
  • Developer: Needs EXACT FILE, LINE, RULE, and FIX DIRECTION — \
the technical detail to act on immediately.
  Serve both in every finding.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Use ONLY the data provided in the [SCAN DATA] block. Do not invent \
rule IDs, file names, or vulnerabilities not present in the data.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, \
or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  Findings in Section 2 MUST follow severity order: \
ERROR → WARNING → INFO. The data block is pre-sorted — maintain \
that order.
5.  Every finding in Section 2 (Part B) MUST follow the exact \
four-part structure defined in Section 2 instructions — no exceptions.
6.  The attacker scenario in Section 2 (part c) MUST:
    a. Reference the specific file and line number from [SCAN DATA].
    b. Be written as a concrete narrative — do NOT use abstract \
language like "could allow data exposure."
    c. Explain how an attacker would reach this code flaw from \
outside the application — not just what the flaw is internally.
7.  The plain-English Vulnerability Name column in the Section 2 \
Part A table MUST use the pre-computed 'Vulnerability' label from \
[SCAN DATA] — do not use the raw Rule ID as the primary label.
8.  The false positive caveat from [SCAN DATA] MUST be reproduced \
verbatim in Section 1 as designated — do not paraphrase or omit it.
9.  Remediation items in Section 4 MUST be ordered by priority: \
most critical first.
10. Every remediation item in Section 4 MUST follow the exact \
structure with Owner and Timeline tags.
11. Do NOT include code snippets, rule fix syntax, or terminal \
commands in Section 4 — plain-English steps only.
12. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 paths: Critical / At Risk / Secure.
    b. Use this path determination logic:
       - ANY ERROR severity finding → Critical path
       - No ERROR but WARNING findings exist → At Risk path
       - Only INFO findings or none → Secure path
    c. Mark the matching path with [ YOU ARE HERE ].
    d. Always show all 3 paths — never omit one.
13. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
14. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary

Before the verdict paragraph, produce a Markdown metadata table with
exactly these two columns:
| Field | Value |
|---|---|
| Report Generated By | NetShieldAI Semgrep SAST |
| Scan Target | {scan_target} |
| Scan Date | {scan_date} |
| Scan Tool | {tool} |
| Language | {language} |
| Framework | {framework} |
| Files Scanned | {files_scanned} |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | [Secure / At Risk / Critical] | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | {total_count} | One sentence on whether this volume is typical or elevated
- Dominant Vulnerability Pattern | [identifying the most frequent category] | One sentence on what this pattern indicates
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

**Important — False Positive Notice:**
{false_positive_note}

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|

Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. Critical Code Flaws Analysis

**Part A — Findings Summary Table**
Produce a Markdown table with exactly these six columns:
| # | Severity | Vulnerability | Rule ID | Location | Priority |
|---|---|---|---|---|---|

Column guidance:
- **Vulnerability**: Use the pre-computed plain-English label from \
[SCAN DATA] — NOT the raw Rule ID as the primary identifier.
- **Rule ID**: Include the raw Rule ID in this column for developer \
reference — secondary to the plain-English name.
- **Location**: Format as `filename — Line N`
- **Priority**: Critical — Fix Now / High — Fix Soon / Medium — Monitor / \
Low — No Action Needed

**Part B — Deep Dive Per Finding**
For each finding in [SCAN DATA], follow this EXACT four-part structure:

**Finding #[N] — [Plain-English Vulnerability Name] | ERROR / WARNING / INFO**
**Rule**: `[Rule ID]`
**Location**: `[file] — Line [N]`

**a. Plain-English Explanation**
What is this vulnerability? 2–3 sentences for a non-technical reader. \
Explain what this piece of code does first, then explain what is \
dangerously wrong with it. Use an analogy if it helps. \
Never lead with the Rule ID or technical name — lead with \
what it means in real-world terms.

**b. Business Impact Assessment**
Produce a Markdown table with exactly these two columns:
| Impact Dimension | Rating |
|---|---|
| Financial | Low / Medium / High |
| Data Risk | Low / Medium / High |
| Reputation | Low / Medium / High |

Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose if an attacker reaches \
and exploits this code flaw?

**c. Attacker Scenario**
Write a concrete narrative (3–5 sentences). \
Start from outside the application — how does an attacker reach \
this specific line of code? \
Reference the actual file name and line number from [SCAN DATA]. \
End with what the attacker achieves.
Do NOT use abstract language — write it as a story.
Example: "A user visiting your application's file upload page \
submits a specially crafted filename containing '../../../etc/passwd'. \
Your code at {file}:{line} passes this filename directly to a \
file-reading function without checking whether the path stays \
within the intended directory. The server opens and returns the \
system's password file, giving the attacker a list of all \
system user accounts."

**d. Fix Direction**
- What specifically needs to change in this area of the code — \
in plain English, no syntax.
- Why this fix works, explained so a non-developer understands \
the reasoning.
- Which developer or team owns this file or module.
- No code snippets — conceptual direction only.

#### 3. Code Pattern Analysis
Rather than generic secure coding advice, this section analyses \
the PATTERNS across all findings in [SCAN DATA]:

- Identify the top 2–3 recurring vulnerability categories \
(e.g., if 5 findings are injection-related, that is a pattern).
- For each pattern:
  a. Name it in plain English.
  b. State how many findings share this pattern.
  c. Explain what this pattern tells us about the codebase's \
security culture or development practices — not just the technical flaw.
  Example: "Three injection-related findings in the same module \
suggests that user input is not being consistently validated \
before being used in sensitive operations — this is a development \
practice gap, not just an isolated bug."
  d. One sentence on the systemic fix — what practice or process \
change would eliminate this entire pattern, not just individual findings?

#### 4. Remediation Plan
Provide exactly 4 remediation items ordered by priority: \
most critical first.
Each item MUST follow this exact structure:
  **Issue**: [Specific finding or pattern this addresses — \
reference file/line for developer, plain-English description \
for business owner]
  **Action**: [Plain step-by-step — what needs to happen, \
who needs to do it — no code syntax]
  **Benefit**: [One sentence — what risk does this eliminate?]
  **Owner**: [Dev Team / Security Team / Both / Management]
  **Timeline**: [Critical — Immediate / High — This Sprint / \
Medium — This Quarter / Low — When Possible]

After the 4 items, write one sentence on the overall remediation \
effort — is this a quick developer afternoon or a systematic \
codebase audit?

#### 5. Risk Score Breakdown

Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Injection Risk
2. Secret Exposure
3. Data Flow Safety
4. Code Quality

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Determine the correct path from [SCAN DATA] using this logic:
- ANY ERROR severity finding present → Critical path
- No ERROR but WARNING findings exist → At Risk path
- Only INFO findings or no findings → Secure path
Mark the correct path with [ YOU ARE HERE ]. Leave others unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your codebase contains confirmed security flaws that could be \
exploited if this application is live or deployed soon.

→ Step 1: [Most urgent action — specific to highest severity \
ERROR finding and its file/line]
→ Step 2: [Second action — address next ERROR finding or \
dominant pattern]
→ Step 3: [Who to escalate to — Security Lead, CTO, or \
external code reviewer]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WARNING-level issues were found that are likely real flaws \
and should be verified and fixed before the next release.

→ Step 1: [Most urgent WARNING finding — specific to file/line]
→ Step 2: [Address the dominant vulnerability pattern found]
→ Step 3: [Process improvement — e.g., add SAST to CI/CD pipeline]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No ERROR or WARNING findings detected. Your codebase is in \
good shape — focus on maintaining secure development practices.

→ Step 1: [Review any INFO findings as low-priority improvements]
→ Step 2: [One proactive code hardening recommendation]
→ Step 3: [Integrate SAST into the regular development workflow]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must reference actual findings from [SCAN DATA].
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed — do not alter them.
- Path determination logic is fixed as defined above.

================================================================================
[SCAN DATA]
================================================================================
Tool               : {tool}
Scan Target        : {scan_target}
Scan Date          : {scan_date}
Language           : {language}
Files Scanned      : {files_scanned}
Framework          : {framework}
Scan Coverage      : {scan_coverage}
Scan Limitations   : {scan_limitations}

### Summary Counts:
- Error  : {error_count}
- Warning: {warning_count}
- Info   : {info_count}
- Total  : {total_count}

{findings_block}
================================================================================
[END OF SCAN DATA]
================================================================================
"""
    return prompt

def _format_generic_security_summary_prompt(parsed_data: Dict[str, Any]) -> str:
    """
    Crafts a refined, structured prompt for an LLM to analyze unidentified
    NetShieldAI security reports or documents.
    Optimized for:
      - High-quality, consistent LLM output regardless of document type
      - Plain-English translation of technical findings for non-expert end users
      - Structured prompt engineering (role / task / constraints / data / format)
      - Document type auto-detection built in Python before injection
      - Truncation warning with character counts if content is cut
      - Confidence framing per finding since source is unstructured
      - Enforced per-finding structure with attacker narratives and business impact scoring
      - Owner-tagged, timeline-aware remediation (no code snippets)
      - Structured Markdown scorecards and clear business impact analysis
      - Gemini-optimized: Clean Markdown tables, no image libraries, emojis, or ASCII required
    """

    # --- 1. Extract Raw Text ---
    raw_text     = parsed_data.get("raw_text", "No text provided.")
    full_length  = len(raw_text)
    TEXT_LIMIT   = 4000
    was_truncated = full_length > TEXT_LIMIT
    text_to_use  = raw_text[:TEXT_LIMIT]

    # --- 2. Document Type Classifier ---
    # Attempt to identify the document type from keyword signals in the raw text
    # so the LLM has context before analysis begins
    text_lower = raw_text[:2000].lower()  # Only scan first 2000 chars for efficiency

    DOCUMENT_TYPE_SIGNALS = {
        "Penetration Test Report"    : ["penetration test", "pentest", "pen test",
                                        "exploitation", "post-exploitation",
                                        "lateral movement", "privilege escalation"],
        "Nmap / Port Scan Report"    : ["nmap", "open port", "closed port",
                                        "syn scan", "service version", "os detection"],
        "Web Application Scan"       : ["owasp", "zap", "burp", "xss",
                                        "sql injection", "csrf", "web application",
                                        "http response", "cookie"],
        "SSL/TLS Assessment"         : ["ssl", "tls", "certificate", "cipher suite",
                                        "tls 1.0", "tls 1.1", "poodle", "heartbleed"],
        "Network Traffic Analysis"   : ["packet capture", "pcap", "wireshark",
                                        "tshark", "protocol", "tcp stream",
                                        "bandwidth", "throughput"],
        "SAST / Code Review"         : ["semgrep", "sast", "static analysis",
                                        "code review", "cwe", "rule id",
                                        "source code", "tainted"],
        "API Security Assessment"    : ["api", "endpoint", "rest", "graphql",
                                        "swagger", "openapi", "http method",
                                        "authentication header"],
        "SQL Injection Audit"        : ["sqlmap", "sql injection", "boolean-based",
                                        "time-based", "union-based", "database dump"],
        "Cloud Security Assessment"  : ["aws", "azure", "gcp", "s3 bucket",
                                        "iam policy", "cloud", "misconfigured",
                                        "public bucket"],
        "Firewall / Network Policy"  : ["firewall", "acl", "access control list",
                                        "ingress", "egress", "network policy",
                                        "allow rule", "deny rule"],
        "Incident Report"            : ["incident", "breach", "data leak",
                                        "compromised", "unauthorized access",
                                        "forensics", "ioc", "indicator of compromise"],
        "Vendor Security Assessment" : ["vendor", "third party", "supplier",
                                        "questionnaire", "compliance",
                                        "iso 27001", "soc 2"],
        "Vulnerability Disclosure"   : ["cve-", "cvss", "vulnerability disclosure",
                                        "advisory", "patch", "affected versions"],
    }

    detected_type       = "Unidentified Security Document"
    detection_confidence = "Low"
    matched_signals     = []

    best_match_count = 0
    for doc_type, signals in DOCUMENT_TYPE_SIGNALS.items():
        matches = [s for s in signals if s in text_lower]
        if len(matches) > best_match_count:
            best_match_count = len(matches)
            detected_type    = doc_type
            matched_signals  = matches

    if best_match_count >= 3:
        detection_confidence = "High"
    elif best_match_count >= 1:
        detection_confidence = "Medium"
    else:
        detected_type        = "Unidentified Security Document"
        detection_confidence = "Low"

    # --- 3. Build Truncation Warning (Plain Text) ---
    if was_truncated:
        truncation_warning = (
            f"**TRUNCATION WARNING:** The original document is {full_length:,} characters. "
            f"Only the first {TEXT_LIMIT:,} characters were provided to this analysis "
            f"({full_length - TEXT_LIMIT:,} characters were cut). Findings identified "
            f"near the end of the document may be incomplete or missing entirely. "
            f"For a complete analysis, the full document should be re-submitted in segments."
        )
    else:
        truncation_warning = (
            f"**DOCUMENT COMPLETE:** Full document provided ({full_length:,} characters). "
            f"No content was truncated."
        )

    # --- 4. Build Coverage & Limitations ---
    scan_coverage = (
        f"Text contents of the provided unstructured document detected as '{detected_type}'"
    )
    scan_limitations = (
        "Live scanning, code execution, network probing, or independent "
        "verification of the findings described in the document"
    )

    # --- 5. Compose Prompt ---
    prompt = f"""\
You are **NetShieldAI's Senior Security Analyst** — an expert at extracting, \
interpreting, and communicating security findings from any type of security \
document clearly and actionably for both business owners and technical teams.

================================================================================
ROLE & OBJECTIVE
================================================================================
Analyze the security document provided in the [DOCUMENT CONTENT] block below \
and produce a professional "Security Document Briefing" report in exactly \
6 sections.

This document has been pre-classified as: **{detected_type}** \
(Detection Confidence: {detection_confidence}).
Use this classification to calibrate your analysis — if the classification \
seems incorrect based on the content, state your own assessment in Section 1 \
and explain why.

Your #1 priority is CLARITY FOR THE END USER:
- Avoid raw technical jargon wherever possible.
- When a technical term is unavoidable, always follow it with a plain-English \
explanation in parentheses.
  Example: "CVE (Common Vulnerabilities and Exposures — a standardised \
reference number for a publicly known security flaw, like a library \
catalogue number for software weaknesses)"
  Example: "CVSS Score (a standardised severity rating from 0–10 — \
higher means more critical, 9–10 is considered the most dangerous)"
  Example: "IOC — Indicator of Compromise (a digital clue that suggests \
a system has been attacked or breached — like unusual login times, \
strange outbound connections, or unexpected files)"
  Example: "Lateral Movement (when an attacker who has broken into one \
system uses it as a stepping stone to move deeper into the network, \
accessing other machines from the inside)"
  Example: "Privilege Escalation (when an attacker with limited access \
finds a way to grant themselves administrator-level control — like a \
guest at a hotel finding a way into the manager's office)"
- Because the document type is not always known in advance, always \
define technical terms even if they seem basic — the reader may \
have no security background at all.
- Write for two audiences simultaneously:
  • Business Owner: Needs RISK, BUSINESS IMPACT, and WHAT TO DO.
  • Technical Team: Needs FINDING DETAIL, EVIDENCE, and FIX DIRECTION.
  Serve both in every finding.

================================================================================
STRICT CONSTRAINTS — FOLLOW EXACTLY
================================================================================
1.  Extract findings ONLY from the [DOCUMENT CONTENT] block. Do not \
invent, assume, or supplement findings not present in the document.
2.  Output clean Markdown ONLY. Never output raw JSON, code blocks, or XML.
3.  Do NOT change, skip, or reorder the six report sections listed below.
4.  Every finding in Section 2 (Part B) MUST follow the exact four-part \
structure defined in Section 2 instructions — no exceptions.
5.  Every finding in Section 2 MUST include a Confidence Level tag \
indicating how clearly this finding is stated in the source document:
    Clearly Stated / Implied / Inferred from Context
6.  Business Impact Score in Section 2 MUST use this exact format:
    💰 Financial: [Low/Medium/High] | 🔒 Data Risk: [Low/Medium/High] \
| 🏢 Reputation: [Low/Medium/High]
7.  The attacker scenario in Section 2 (part c) MUST be written as a \
concrete narrative — do NOT use abstract language like "could allow \
unauthorized access." If the document does not provide enough detail \
for a full scenario, write the most realistic scenario based on the \
finding type and flag it with "Inferred".
8.  Findings in Section 2 Part A table MUST be ordered by severity: \
Critical → High → Medium → Low → Informational.
9.  Every remediation item in Section 4 MUST follow the exact structure \
with Owner and Timeline tags — no code snippets or commands.
10. Remediation items in Section 4 MUST be ordered by priority: \
most critical first.
11. The Decision Guide (Section 6) MUST:
    a. Provide exactly 3 paths: Critical / At Risk / Secure.
    b. Use this path determination logic based on the highest severity \
finding extracted:
       - Any Critical or High severity finding → Critical path
       - No Critical/High but Medium findings exist → At Risk path
       - Only Low/Info findings or none → Secure path
    c. Mark the matching path with [ YOU ARE HERE ].
    d. Always show all 3 paths — never omit one.
12. Do NOT use emoji anywhere in the report output — this is a \
professional security briefing, not a consumer interface. \
All risk indicators, priority labels, and status labels must \
use plain text as defined in the report structure instructions.
13. Do NOT use Unicode box-drawing characters, ASCII art, or \
visual gauge bars anywhere in the output. All structured data \
must be presented in Markdown tables.

================================================================================
REPORT STRUCTURE — OUTPUT EXACTLY THESE SIX SECTIONS
================================================================================

#### 1. Executive Summary — Document Overview

Before the verdict paragraph, produce a Markdown metadata table with
exactly these two columns:
| Field | Value |
|---|---|
| Report Generated By | NetShieldAI Generic Security Analyser |
| Scan Target | Unidentified Document |
| Scan Date | N/A |
| Detected Document Type | {detected_type} |
| Detection Confidence | {detection_confidence} |
| Matched Signals | {", ".join(matched_signals) if matched_signals else "None"} |
| Content Length | {full_length} characters |
| Truncated | {"Yes" if was_truncated else "No"} |
| Report Classification | Internal Use Only |
| Prepared By | NetShieldAI Automated Security Analysis |

This table anchors the report to a specific scan event and ensures
the reader can immediately verify which system was assessed and when.

{truncation_warning}

**Analyst Confidence Statement**
Write one sentence assessing the overall confidence of this analysis based on the \
detection confidence of '{detection_confidence}' and whether the document was truncated.

**Plain-English Risk Summary**
Write exactly 3 sentences structured as follows:
Sentence 1: What was assessed and what the overall result is —
            stated as plainly as possible for a non-technical reader.
Sentence 2: What the most serious finding means in terms of
            real-world business consequences — not technical impact.
Sentence 3: What the single most important next step is and
            who should take it.

This paragraph must be written as if explaining to a business owner
who has no technical background and five minutes to decide whether
to act. Avoid all technical terminology. If a technical term is
unavoidable, define it immediately in the same sentence.

Produce a Markdown risk verdict table with exactly these columns:
| Metric | Value | Significance |
|---|---|---|
Rows to include:
- Overall Security Posture | [Secure / At Risk / Critical] | One sentence on what this verdict means for the business today
- Highest Severity Finding | [finding name or None] | One sentence on why this is the most dangerous item
- Total Findings | [count] | One sentence on whether this volume is typical or elevated
- Immediate Action Required | [Yes / No] | One sentence on the consequence of delaying action

Replace the scan coverage disclaimer prose sentence with a Markdown table:
| What This Assessment Covered | What This Assessment Did NOT Cover |
|---|---|
| [item 1] | [item 1] |
| [item 2] | [item 2] |
| [item 3] | [item 3] |

Populate this table using the pre-computed scan_coverage and
scan_limitations values from the scan data. Split each into
individual line items — do not combine into a single cell.
This is mandatory. Readers must immediately understand the
boundaries of this assessment before acting on its findings.

**Top 3 Findings Requiring Attention**
Produce a Markdown table with exactly these columns:
| Priority | Finding | Risk Level | Recommended Owner | Estimated Effort |
|---|---|---|---|---|

Rules:
- List exactly 3 findings ordered by severity, highest first.
- If fewer than 3 findings exist, list all available findings.
- If no findings exist, produce one row stating:
  | 1 | No significant findings detected | Low | N/A | N/A |
- Estimated Effort must be one of: Low / Medium / High / Unknown
- Recommended Owner must be one of:
  Dev Team / IT Support / Both / Management / ISP
- This table is the single most actionable section of the entire report
  for a business owner who will read nothing else.

**Industry Comparison Context**
Write 2-3 sentences addressing:
a. How the findings compare to what is typical for an organisation
   of this type running this kind of system. Be specific — reference
   the scan type and target context from the scan data.
b. Whether the combination of findings detected represents an isolated
   issue or a pattern that suggests a broader security culture gap.
c. One sentence on what a well-hardened equivalent system would look like
   in contrast to what was found.

Do not use generic filler. Every sentence must reference something
specific from the scan data.

#### 2. Key Security Findings Analysis

**Part A — Findings Summary Table**
Produce a Markdown table with exactly these six columns:
| # | Severity | Finding | Source Evidence | Confidence | Priority |
|---|---|---|---|---|---|

Column guidance:
- **Finding**: Plain-English name of the security issue.
- **Source Evidence**: A brief quote or reference from the document \
that confirms this finding — keep under 10 words, paraphrase \
if needed.
- **Confidence**: Clearly Stated / Implied / Inferred from Context
- **Priority**: Critical — Fix Now / High — Fix Soon / Medium — Monitor / \
Low — No Action Needed

**Part B — Deep Dive Per Finding**
For each significant finding extracted, follow this EXACT \
four-part structure. Cover the top 3–5 most critical findings \
— do not attempt to cover every minor item if the document \
contains many.

**Finding #[N] — [Plain-English Finding Name] | \
CRITICAL / HIGH / MEDIUM / LOW**
**Confidence**: [Clearly Stated / Implied / Inferred from Context]

**a. Plain-English Explanation**
What is this finding? 2–3 sentences for a non-technical reader. \
Lead with what it means in real-world terms, not the technical name. \
If this is a well-known vulnerability type (e.g., SQL Injection, \
CVE), explain it plainly before using the technical term.

**b. Business Impact Assessment**
Produce a Markdown table with exactly these two columns:
| Impact Dimension | Rating |
|---|---|
| Financial | Low / Medium / High |
| Data Risk | Low / Medium / High |
| Reputation | Low / Medium / High |

Follow with 1-2 sentences explaining why these ratings were assigned — \
what specifically could the business lose if this \
finding is exploited or left unaddressed.

**c. Attacker Scenario or Risk Materialisation**
Write a concrete narrative (3–5 sentences). \
If the document describes an active incident, describe what \
already happened. If it describes a vulnerability, write what \
an attacker would do to exploit it. \
Flag the scenario with the appropriate confidence level. \
Do NOT use abstract language.

**d. Fix Direction or Response Action**
- What specifically needs to happen — in plain English.
- Who needs to do it.
- Why this action addresses the finding.
- No code snippets or commands.

#### 3. Document-Specific Context Analysis
Rather than generic security advice, this section analyses what \
the DOCUMENT TYPE and its specific findings tell us about the \
organisation's broader security posture:

- Based on the detected document type and findings, write 2–3 \
observations about what these findings collectively suggest \
about the organisation's security maturity or practices.
- Each observation must:
  a. Be specific to the findings in THIS document — not generic advice.
  b. Distinguish between a one-off issue and a systemic pattern \
if the evidence supports it.
  c. State what the observation implies for the business \
in plain English.
- End with one sentence on what TYPE of follow-up assessment \
would be most valuable given what this document reveals.

#### 4. Recommended Actions
Provide exactly 4 remediation or response items ordered by priority.
Each item MUST follow this exact structure:
  **Issue**: [Specific finding this addresses]
  **Action**: [Plain step-by-step — no commands or code]
  **Benefit**: [One sentence — what risk does this eliminate \
or reduce?]
  **Owner**: [Dev Team / IT Support / Security Team / \
Management / Both]
  **Timeline**: [Critical — Immediate / High — This Sprint / \
Medium — This Quarter / Low — When Possible]

After the 4 items, write one sentence on the overall response \
effort — is this a quick fix or a multi-team remediation project?

#### 5. Risk Score Breakdown

Produce a professional security scorecard using a Markdown table. Score each
category on a scale of 0 to 10, where 10 is perfectly secure and 0 is
critically exposed. Derive all scores strictly from the scan data — do not
invent numbers.

Produce a Markdown table with exactly these four columns:
| Category | Score (0-10) | Risk Level | Justification |
|---|---|---|---|

Categories to score:
1. Finding Severity
2. Risk Coverage
3. Remediation Clarity
4. Document Completeness

Rules for the Score Breakdown:
- Risk Level must be exactly one of: SAFE / MODERATE / ELEVATED / CRITICAL
- Justification must be one plain-English sentence explaining the score
  based strictly on the data provided. If confidence in any category is Low, note it with UNSCORED rather than inventing a score.
- After the table, produce a second summary table with exactly these columns:
  | Overall Grade (0-10) | Final Verdict |
  |---|---|
- Overall Grade is the arithmetic average of the four category scores,
  rounded to one decimal place.
- Final Verdict must be exactly one of: SECURE / GUARDED / AT RISK / CRITICAL

#### 6. What Happens Next — Your Decision Guide
Produce a plain-English decision guide with exactly 3 paths. \
Determine the correct path based on the highest severity finding \
extracted from the document:
- Any Critical or High severity finding → Critical path
- No Critical/High but Medium findings exist → At Risk path
- Only Low/Info findings or no significant findings → Secure path
Mark the correct path with [ YOU ARE HERE ]. Leave others unmarked.

Use this EXACT template:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 1 — CRITICAL                    [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This document contains or describes serious security issues \
that require immediate attention.

→ Step 1: [Most urgent action — specific to the highest \
severity finding extracted]
→ Step 2: [Second action — address next priority finding]
→ Step 3: [Who to escalate to and what to tell them]
Recommended Timeline: Act within 24 hours.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 2 — AT RISK                     [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Medium-severity issues were identified that should be addressed \
before they escalate or are discovered by an attacker.

→ Step 1: [Most urgent medium-severity finding action]
→ Step 2: [Second action or verification step]
→ Step 3: [Follow-up assessment recommendation]
Recommended Timeline: Address within 1 week.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATH 3 — SECURE                      [[ YOU ARE HERE ] / blank]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
No significant security issues were identified in this document.

→ Step 1: [Address any Low/Info findings as quick wins]
→ Step 2: [Recommend the next appropriate scan or assessment \
based on document type]
→ Step 3: [Long-term security posture maintenance advice]
Recommended Timeline: Review monthly.

Rules for the Decision Guide:
- All 3 paths must always be shown — never omit one.
- Steps must reference actual findings from [DOCUMENT CONTENT].
- [ YOU ARE HERE ] appears on exactly ONE path.
- Timeline lines are fixed — do not alter them.
- Path determination logic is fixed as defined above.

================================================================================
[DOCUMENT CONTENT]
================================================================================
Detected Document Type  : {detected_type}
Detection Confidence    : {detection_confidence}
Matched Signals         : {", ".join(matched_signals) if matched_signals else "None"}
Scan Coverage           : {scan_coverage}
Scan Limitations        : {scan_limitations}

--- DOCUMENT TEXT START ---
{text_to_use}
--- DOCUMENT TEXT END ---
================================================================================
[END OF DOCUMENT CONTENT]
================================================================================
"""
    return prompt

async def summarize_report_with_llm(
    llm_instance: Any, 
    generate_response_func: Callable[[Any, str, int], str], 
    parsed_data: Dict[str, Any], 
    report_type: str
) -> str:
    """
    Generates a natural language summary and remediation steps for a parsed security report
    using the provided LLM instance and its generation function.

    Args:
        llm_instance (Any): The loaded LLM model instance (e.g., Llama, GenerativeModel).
        generate_response_func (Callable): The function responsible for generating a response
                                           from the given LLM instance, prompt, and max_tokens.
        parsed_data (Dict[str, Any]): The structured dictionary parsed from the report.
        report_type (str): The type of the report.

    Returns:
        str: The generated explanation and remediation steps from the LLM.
    """
    prompt = ""
    if report_type.lower() == "nmap":
        prompt = _format_nmap_summary_prompt(parsed_data)
    elif report_type.lower() == "zap":
        prompt = _format_zap_summary_prompt(parsed_data)
    elif report_type.lower() == "sslscan":
        prompt = _format_sslscan_summary_prompt(parsed_data)
    elif report_type.lower() == "pcap":
        prompt = _format_traffic_analysis_prompt(parsed_data)
    elif report_type.lower() == "sql":
        prompt = _format_sql_summary_prompt(parsed_data)
    elif report_type.lower() == "killchain":
        prompt = _format_killchain_summary_prompt(parsed_data)
    elif report_type.lower() in ("api_scanner", "api"):
        prompt = _format_api_scan_summary_prompt(parsed_data)
    elif report_type.lower() == "semgrep":
        prompt = _format_semgrep_summary_prompt(parsed_data)
    elif report_type.lower() == "generic_security_report":
        prompt = _format_generic_security_summary_prompt(parsed_data)
    else:
        logger.warning(f"Unsupported report type: {report_type}")

    logger.info(f"Generating summary for {report_type} report...")

    # Call the passed generate_response_func
    llm_response = await generate_response_func(llm_instance, prompt, max_tokens=config.DEFAULT_SUMMARIZE_MAX_TOKENS)
    
    # If the response is a dict (Gemini), extract 'text'
    if isinstance(llm_response, dict):
        return llm_response.get("text", "")
        
    return llm_response

async def summarize_chat_history_segment(
    llm_instance: Any,
    generate_response_func: Callable[[Any, str, int], str],
    history_segment: List[Dict[str, str]],
    max_tokens: int = config.DEFAULT_SUMMARIZE_MAX_TOKENS
) -> str:
    """
    Uses the LLM to summarize a segment of the chat history for context
    window compression during ongoing NetShieldAI security analysis sessions.

    Args:
        llm_instance (Any): The loaded LLM model instance (e.g., Llama, GenerativeModel).
        generate_response_func (Callable): Async function that accepts (llm_instance,
                                           prompt, max_tokens) and returns a string
                                           or {'text': str} dict.
        history_segment (List[Dict[str, str]]): A list of message dicts with 'role'
                                                and 'content' keys, representing the
                                                conversation turns to summarize.
        max_tokens (int): Maximum tokens for the generated summary output.

    Returns:
        str: A concise, structured summary of the conversation segment,
             or an empty string if the segment is empty,
             or a fallback error string if generation fails.
    """

    # --- 1. Guard: Empty Segment ---
    if not history_segment:
        logger.debug("summarize_chat_history_segment called with empty segment — returning ''.")
        return ""

    # --- 2. Token Budget Guard ---
    # Approximate token count: ~4 characters per token (conservative estimate)
    # If the segment text exceeds the budget, trim from the oldest messages first
    CHARS_PER_TOKEN   = 4
    # Reserve half of max_tokens for the summary output; use the other half for input
    INPUT_CHAR_BUDGET = (max_tokens // 2) * CHARS_PER_TOKEN

    total_chars = sum(
        len(msg.get("role", "")) + len(msg.get("content", ""))
        for msg in history_segment
    )

    if total_chars > INPUT_CHAR_BUDGET:
        logger.warning(
            f"History segment ({total_chars} chars across {len(history_segment)} turns) "
            f"exceeds input budget ({INPUT_CHAR_BUDGET} chars). "
            f"Trimming oldest messages first."
        )
        # Trim from the front (oldest messages) until within budget
        trimmed_segment = list(history_segment)
        while trimmed_segment and total_chars > INPUT_CHAR_BUDGET:
            removed = trimmed_segment.pop(0)
            total_chars -= len(removed.get("role", "")) + len(removed.get("content", ""))

        if not trimmed_segment:
            logger.error("History segment too large even after trimming — cannot summarize.")
            return "(Conversation segment too large to summarize.)"
    else:
        trimmed_segment = history_segment

    # --- 3. Build Conversation Block ---
    # Validate each message and skip malformed entries with a warning
    conversation_lines = []
    skipped_count = 0

    for i, msg in enumerate(trimmed_segment):
        role    = msg.get("role")
        content = msg.get("content")

        if not role or not content:
            logger.warning(
                f"Skipping malformed message at index {i} in history segment "
                f"(missing 'role' or 'content'): {msg}"
            )
            skipped_count += 1
            continue

        conversation_lines.append(f"{role.strip().capitalize()}: {content.strip()}")

    if not conversation_lines:
        logger.error(
            "No valid messages remain after validation "
            f"({skipped_count} malformed entries skipped)."
        )
        return "(No valid messages to summarize.)"

    conversation_block = "\n".join(conversation_lines)

    if skipped_count > 0:
        logger.warning(f"{skipped_count} malformed message(s) were skipped during summarization.")

    # --- 4. Build Summarization Prompt ---
    # Purpose-aware: tells the LLM exactly WHY it is summarizing
    # and WHAT the summary will be used for — produces significantly
    # better output than a generic "summarize this" instruction
    summarization_prompt = f"""\
You are a context compression assistant for NetShieldAI — a cybersecurity \
analysis platform. Your task is to summarize a segment of a security \
analysis conversation so that the summary can replace the full conversation \
history in the active context window.

The summary will be used to:
1. Preserve the key security findings, user questions, and conclusions \
discussed so far.
2. Allow the conversation to continue without losing important context.
3. Be compact enough to free up space for new messages and analysis.

### STRICT SUMMARIZATION RULES:
1. Output the summary ONLY — no preamble, no labels, no "Here is the summary:" prefix.
2. Write in third-person neutral past tense: \
"The user asked about...", "NetShieldAI identified...", "It was concluded that..."
3. Preserve ALL of the following if present:
   - Specific vulnerability names, CVEs, or finding titles mentioned.
   - Specific file names, IP addresses, URLs, or port numbers discussed.
   - Any remediation steps that were agreed upon or recommended.
   - Any unresolved questions or topics the user was still investigating.
4. Do NOT preserve:
   - Greetings, pleasantries, or filler conversation.
   - Repetition of the same point across multiple turns.
   - Raw scan data that was already analysed and summarized in the discussion.
5. Target length: 3–6 sentences. Never exceed 10 sentences regardless of \
segment length.
6. If the conversation covered multiple distinct security topics, use one \
sentence per topic.

================================================================================
[CONVERSATION SEGMENT TO SUMMARIZE]
================================================================================
{conversation_block}
================================================================================
[END OF CONVERSATION SEGMENT]
================================================================================
"""

    # --- 5. Generate Summary ---
    logger.info(
        f"Summarizing chat history segment: "
        f"{len(trimmed_segment)} turns, "
        f"{len(conversation_block)} chars."
    )

    summary_response = await generate_response_func(
        llm_instance,
        summarization_prompt,
        max_tokens=max_tokens
    )

    # --- 6. Normalise Response ---
    # generate_response_func may return either a plain string (Llama-style)
    # or a dict with a 'text' key (Gemini-style) — handle both safely
    if isinstance(summary_response, dict):
        summary_text = summary_response.get("text") or ""
    elif isinstance(summary_response, str):
        summary_text = summary_response
    else:
        logger.warning(
            f"Unexpected response type from generate_response_func: "
            f"{type(summary_response)} — returning fallback."
        )
        return "(Error summarizing previous conversation: unexpected response format.)"

    summary_text = summary_text.strip()

    if not summary_text:
        logger.warning("generate_response_func returned an empty summary — returning fallback.")
        return "(Summary could not be generated.)"

    logger.info(
        f"Chat history summary generated successfully "
        f"({len(summary_text)} chars, ~{len(summary_text) // CHARS_PER_TOKEN} tokens)."
    )

    return summary_text