# Microsoft Sentinel Detection Lab

A SOC lab built on Microsoft Azure, featuring end-to-end log ingestion, custom KQL detection rules mapped to MITRE ATT&CK TTPs, adversary simulation, automated triage playbooks, and a live analysis dashboard. Built to replicate real enterprise SOC environments and demonstrate analyst-level detection engineering.

---
## Architecture

The lab pipeline flows as follows:

**Windows Server 2025 VM → Azure Monitor Agent → Data Collection Rules → Log Analytics Workspace → Microsoft Sentinel → KQL Analytics Rules → Incidents → Logic App Playbooks**

All resources are contained within the `SentinelLab-RG` resource group in Azure.

**Core components:**

- Microsoft Sentinel (SIEM + SOAR)
- Log Analytics Workspace (`SentinelLab-LAW`)
- Windows Server 2025 VM (`SentinelLab-Win01`) — West Europe
- Azure Monitor Agent (AMA) with Data Collection Rules
- Sysmon with SwiftOnSecurity baseline config
- 2 Logic App playbooks for automated response
- Custom SOC workbook dashboard

<img width="1907" height="884" alt="image" src="https://github.com/user-attachments/assets/891a2780-a195-400d-bca3-480984ff87bf" />

---
## Phase 1 — Environment Setup

**Tools:** Azure Portal, Microsoft Sentinel, Log Analytics Workspace, Content Hub

Deployed a Log Analytics Workspace and attached Microsoft Sentinel on top of it. Installed the following Content Hub solution packs to pre-load detection templates and data connector schemas:

- Windows Security Events (Microsoft)
- Microsoft Defender XDR (Microsoft)
- Microsoft Defender for Endpoint (Microsoft)

---
## Phase 2 — Endpoint Onboarding & Log Ingestion

**Tools:** Azure Monitor Agent, Data Collection Rules, Sysmon, PowerShell, KQL

Deployed a Windows Server 2025 VM and onboarded it as a managed endpoint. Configured three Data Collection Rules to stream telemetry into the Log Analytics Workspace:

- `SentinelLab-DCR` — Windows Event Logs (Application, Security, System)
- `SentinelLab-DCR-Sysmon` — Sysmon Operational channel (`Microsoft-Windows-Sysmon/Operational!*`)
- `SentinelLab-DCR-SecurityEvents` — Security Events via the Windows Security Events via AMA connector (routes to the `SecurityEvent` table)

Installed Sysmon using the SwiftOnSecurity baseline configuration to capture process creation, network connections, registry modifications, DNS queries, and process access events. Added a custom ProcessAccess rule to capture LSASS access (EventID 10) for credential dumping detection.

### Initial VM Page
<img width="1864" height="893" alt="image" src="https://github.com/user-attachments/assets/78b4e027-78ba-4d16-b068-6fad52ac5f3b" />

### Sysmon Installed
<img width="1337" height="749" alt="image" src="https://github.com/user-attachments/assets/40d5016a-1bac-4991-8fe7-87a25b88842d" />

### Data Collection Rules
<img width="1857" height="364" alt="image" src="https://github.com/user-attachments/assets/588a9f15-774e-40c8-8258-d34a590dcf54" />

### VM Monitoring Rule
<img width="1163" height="573" alt="image" src="https://github.com/user-attachments/assets/39df1af5-5364-4f17-9ec0-17edd0420cda" />

**Verification queries — both confirmed data flowing:**

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count() by EventID, Computer
| order by count_ desc
```

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where TimeGenerated > ago(1h)
| summarize count() by EventID
```

### Security Event Logs with KQL
<img width="1043" height="657" alt="image" src="https://github.com/user-attachments/assets/d9da6175-6586-4871-b753-02a3f128f997" />

### Sysmon Logs with KQL
<img width="1088" height="669" alt="image" src="https://github.com/user-attachments/assets/bec984e7-7332-4222-999b-0d2d1c0ff19d" />

---
## Phase 3 — KQL Detection Rules

**Tools:** Microsoft Sentinel Analytics, KQL, MITRE ATT&CK framework

Authored 10 custom scheduled analytics rules covering credential access, persistence, execution, privilege escalation, and lateral movement. All rules are stored as individual `.kql` files in `/detections/`.

|Rule|MITRE Tactic|MITRE Technique|Severity|Data Source|
|---|---|---|---|---|
|Brute Force Detection|Credential Access|T1110|Medium|SecurityEvent|
|Successful Logon After Brute Force|Credential Access|T1078|Medium|SecurityEvent|
|New Local Admin Account Created|Persistence|T1136.001|Medium|SecurityEvent|
|LSASS Memory Access|Credential Access|T1003.001|High|Event (Sysmon)|
|Encoded PowerShell Execution|Execution|T1059.001|Medium|Event (Sysmon)|
|Scheduled Task Creation via CLI|Persistence|T1053.005|Low|Event (Sysmon)|
|Registry Run Key Persistence|Persistence|T1547.001|Low|Event (Sysmon)|
|Suspicious Outbound Network Connection|Command and Control|T1071|Low|Event (Sysmon)|
|Process Injection Detected|Defense Evasion|T1055|High|Event (Sysmon)|
|Special Privileges Assigned to Non-Admin|Privilege Escalation|T1134|Low|SecurityEvent|

All rules configured with:
- 5 minute query frequency
- 1 hour lookback window
- Alert threshold: results > 0
- Entity mapping: Account, Host, IP where applicable
- MITRE tactic and technique mapped per rule

<img width="1863" height="899" alt="image" src="https://github.com/user-attachments/assets/7a800fdc-28ed-42d7-ae43-ca50a2d185e9" />

---
## Phase 4 — Adversary Simulation

**Tools:** Python, PowerShell, ProcDump (Sysinternals), Sysmon, Windows CMD

Built a Python adversary simulation script (`/simulations/adversary_sim.py`) that executes attack techniques sequentially, logs results, and outputs a summary report. Simulations ran directly on the Windows VM to generate real telemetry.

**Techniques simulated:**
- Brute force via `runas` failed login loop → EventID 4625
- New local admin account creation → EventID 4720 + 4732
- LSASS memory dump via ProcDump (Defender disabled temporarily) → Sysmon EventID 10
- Base64 encoded PowerShell execution → Sysmon EventID 1
- Scheduled task creation via `schtasks /create` → Sysmon EventID 1
- Registry run key persistence via `reg add` → Sysmon EventID 13
- Suspicious outbound connection on port 4444 via `Test-NetConnection` → Sysmon EventID 3
- Privilege escalation via local admin logon → EventID 4672

<img width="1919" height="735" alt="image" src="https://github.com/user-attachments/assets/d611cd9e-1db2-43bd-991e-8309aa843787" />

### Initial Alerts (only 5 triggered)
<img width="1524" height="643" alt="image" src="https://github.com/user-attachments/assets/f988118c-86d2-4195-b61a-2db391c9f905" />


**Detection tuning notes:**

- Brute Force rule required lookback window increase from 5 minutes to 1 hour to account for ingestion latency
- New Local Admin rule required join field change from `TargetUserName` to `SubjectUserName` — 4732 events store the group name in TargetUserName, not the added account
- LSASS rule required custom Sysmon ProcessAccess configuration — SwiftOnSecurity baseline does not capture EventID 10 by default
- Process Injection rule excluded `dwm.exe`, `csrss.exe`, `svchost.exe` — legitimate Windows processes generate consistent EventID 8 activity that caused false positive exclusions to filter all results

**Post-Tuning Detection results — 9 of 10 rules validated:**
<img width="1516" height="633" alt="image" src="https://github.com/user-attachments/assets/6ef5a5e7-179b-4567-ac3c-b798a6ca214f" />

| Rule                               | Fired                                                                |
| ---------------------------------- | -------------------------------------------------------------------- |
| Brute Force Detection              | Yes                                                                  |
| Successful Logon After Brute Force | Yes                                                                  |
| New Local Admin Account Created    | Yes                                                                  |
| LSASS Memory Access                | Yes                                                                  |
| Encoded PowerShell Execution       | Yes                                                                  |
| Scheduled Task Creation            | Yes                                                                  |
| Registry Run Key Persistence       | Yes                                                                  |
| Suspicious Outbound Connection     | Yes                                                                  |
| Process Injection Detected         | No — requires dedicated injection tooling (Metasploit/Cobalt Strike) |
| Special Privileges Assigned        | Yes                                                                  |

---
## Phase 5 — SOC Dashboard (Sentinel Workbook)

**Tools:** Microsoft Sentinel Workbooks, KQL, Azure Monitor

Built a custom 5-tile SOC dashboard with a global time range parameter. Dashboard JSON exported to `/workbooks/soc-dashboard.json` for redeployment.

**Tiles:**
1. Alert volume over time — line chart showing hourly alert trends by severity
<img width="1900" height="751" alt="image" src="https://github.com/user-attachments/assets/a5cef095-fdb5-46c7-97bf-acf1519f9e9d" />
2. Alert severity distribution — bar chart showing High/Medium/Low/Informational breakdown
<img width="1834" height="511" alt="image" src="https://github.com/user-attachments/assets/371df6cf-1ca7-404d-97b0-1defcd9af7ba" />
3. Alerts by rule — pie chart showing which detection rules are firing most frequently
<img width="1908" height="601" alt="image" src="https://github.com/user-attachments/assets/6d6874d0-4758-4bff-be8b-7831214bf6d2" />
4. Failed login source locations — geo map of EventID 4625 source IPs
<img width="1435" height="758" alt="image" src="https://github.com/user-attachments/assets/83617d24-4c90-4ec5-9476-ccd195715e10" />
5. Open incidents — grid showing active incidents sorted by time
<img width="1903" height="777" alt="image" src="https://github.com/user-attachments/assets/91b85758-87e3-42d0-b29c-76346310e890" />

---
## Phase 6 — Logic App Automation Playbooks

**Tools:** Azure Logic Apps, Microsoft Sentinel Automation Rules, Office 365 connector

Built two Logic App playbooks attached to automation rules for automated incident triage. ARM templates exported to `/playbooks/` for redeployment.

### Playbook 1 — AutoClose-Informational

Automatically closes any Informational severity incident the moment it is created. Eliminates manual triage for low-fidelity alerts.

**Flow:** Incident created → Check severity == Informational → Update incident status to Closed, classification Undetermined

**Automation rule:** `AutoClose-Informational-Rule` — triggers on incident creation, condition severity = Informational

<img width="1649" height="862" alt="image" src="https://github.com/user-attachments/assets/198650e2-7d29-4efe-844d-5efedc862fcc" />

### Playbook 2 — Email-HighSeverity

Sends an email notification within seconds of a High severity incident being created. Email includes incident number, severity, status, and description.

**Flow:** Incident created → Send email via Office 365 with incident details

**Automation rule:** `Email-HighSeverity-Rule` — triggers on incident creation, condition severity = High

<img width="1655" height="860" alt="image" src="https://github.com/user-attachments/assets/50ec6cc6-d49c-48e3-83a4-bef1d261cb22" />

### Automation Rules
<img width="1853" height="623" alt="image" src="https://github.com/user-attachments/assets/a812fb97-e7f0-4692-9be0-f2c0d875be3d" />

**Validated:** LSASS Memory Access simulation triggered a High severity incident and email notification was received within 5 seconds.

<img width="1143" height="363" alt="image" src="https://github.com/user-attachments/assets/c46aa1da-0e7c-4e2d-ad81-063caa7699a2" />

---

## Repository Structure

```
sentinel-detection-lab/
├── detections/
│   ├── brute-force.kql
│   ├── successful-logon-after-bruteforce.kql
│   ├── new-local-admin.kql
│   ├── lsass-memory-access.kql
│   ├── encoded-powershell.kql
│   ├── scheduled-task.kql
│   ├── registry-run-key.kql
│   ├── suspicious-outbound.kql
│   ├── process-injection.kql
│   └── special-privileges.kql
├── workbooks/
│   └── soc-dashboard.json
├── playbooks/
│   ├── autoclose-informational.json
│   └── email-high-severity.json
├── simulations/
│   └── adversary_sim.py
└── README.md
```

---
## Lessons Learned

- The `SecurityEvent` table and the generic `Event` table are separate in Sentinel — Security Events sent via AMA must be routed through the **Windows Security Events via AMA** data connector specifically to land in `SecurityEvent`. Using a generic DCR routes them to `Event` instead, breaking standard detection queries.
- Sysmon EventID fields like `TargetImage`, `CommandLine`, and `SourceImage` are not queryable as direct columns in the `Event` table — all field extraction requires `EventData contains` or `parse_xml()`. Understanding this is critical for writing Sysmon-based detections.
- ProcessAccess monitoring (EventID 10) is disabled by default in the SwiftOnSecurity Sysmon config to reduce noise. LSASS detection requires explicit configuration of a ProcessAccess rule targeting `lsass.exe`.
- Detection rule lookback windows must account for log ingestion latency. Rules with 5 minute windows frequently miss events that arrive 3–8 minutes after generation. 1 hour lookback is the practical minimum for most detection scenarios.
- Join-based detections (brute force followed by successful logon, account creation followed by group addition) require careful attention to which fields actually carry the relevant identifier across both event types — TargetUserName and SubjectUserName serve different purposes in different EventIDs.
- Gmail is incompatible with the Azure Sentinel Logic App trigger due to Microsoft connector policy restrictions. Office 365 Outlook is required for email automation in Sentinel playbooks.

---
## Skills Demonstrated
- Microsoft Sentinel deployment and configuration
- Log Analytics Workspace management and KQL querying
- Azure Monitor Agent and Data Collection Rule configuration
- Sysmon deployment and custom rule authoring
- Detection engineering — 9 validated KQL analytics rules
- MITRE ATT&CK framework mapping
- Adversary simulation and detection validation
- SOC dashboard design and workbook development
- SOAR automation via Azure Logic Apps
- Azure infrastructure management (VMs, resource groups, Bastion)
- Python scripting for adversary simulation
- PowerShell for Windows endpoint administration
