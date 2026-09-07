# 🛡️ SOC Home Lab — Microsoft Defender for Endpoint, Sentinel & SOAR

A hands-on **SOC / Blue Team Home Lab** designed to simulate a multi-stage attack against a small enterprise environment and investigate the resulting activity using **Microsoft Defender for Endpoint, Microsoft Sentinel, and SOAR**.


---

## 🏗️ Lab Architecture

```text
                         ┌──────────────────────────────┐
                         │      MICROSOFT SECURITY       │
                         │                              │
                         │  Defender for Endpoint (EDR) │
                         │  Microsoft Sentinel (SIEM)   │
                         │  SOAR / Azure Logic Apps      │
                         └──────────────┬───────────────┘
                                        │
                              Detection / Investigation
                                        │
              ┌─────────────────────────┴────────────────────┐
              │                                              │
              ▼                                              ▼
    ┌──────────────────┐                           ┌──────────────────┐
    │    TARGET-PC     │                           │      ADDC        │
    │    Windows 10    │                           │ Windows Server   │
    │ 192.168.10.132   │                           │ Active Directory │
    │                  │                           │ 192.168.10.130   │
    └─────────┬────────┘                           └─────────┬────────┘
              │                                              │
              └──────────────────┬───────────────────────────┘
                                 │
                        ┌────────▼────────┐
                        │   KALI LINUX    │
                        │     Attacker     │
                        │ 192.168.10.133   │
                        └─────────────────┘
````

---

## 🖥️ Lab Environment

| Host / Service                  | Role               | IP               | Platform       |
| ------------------------------- | ------------------ | ---------------- | -------------- |
| `KALI`                          | Attacker           | `192.168.10.133` | Kali Linux     |
| `TARGET-PC`                     | Endpoint           | `192.168.10.132` | Windows 10     |
| `ADDC`                          | Domain Controller  | `192.168.10.130` | Windows Server |
| Microsoft Defender for Endpoint | EDR                | Cloud            | Microsoft      |
| Microsoft Sentinel              | SIEM               | Cloud            | Microsoft      |
| SOAR / Azure Logic Apps         | Automated Response | Cloud            | Microsoft      |

---

# ⚔️ Attack Chain

The lab simulates a multi-stage attack progressing from reconnaissance to data staging and exfiltration.

```text
01 — Reconnaissance / Port Scanning
                ↓
02 — RDP Brute Force
                ↓
03 — Discovery
                ↓
04 — Privilege Escalation
                ↓
05 — Persistence / Scheduled Task
                ↓
06 — Lateral Movement
                ↓
07 — Domain Compromise
                ↓
08 — Defense Evasion
                ↓
09 — Data Staging & Exfiltration
```


---

# 🔎 Custom Microsoft Sentinel Analytic Rules

Five custom detection rules were developed to detect key stages of the attack chain.

| #  | Detection Rule                                     | Severity | MITRE ATT&CK     |
| -- | -------------------------------------------------- | -------- | ---------------- |
| 01 | Nmap Port Scanning Activity Detected               | Medium   | `T1595.001`      |
| 02 | Suspicious Discovery Commands Executed             | Medium   | `T1082`, `T1087` |
| 03 | Windows Security Event Log Cleared                 | High     | `T1070.001`      |
| 04 | Scheduled Task Created                             | Medium   | `T1053.005`      |
| 05 | Suspicious RDP Brute Force with Success Validation | Medium   | `T1110.001`      |



The detections use **KQL** against Windows security telemetry collected in Microsoft Sentinel.

---

# 🧠 Detection & Investigation

The project demonstrates investigation techniques commonly used by a SOC Tier 1 analyst:

* Alert triage
* Incident investigation
* Process and command-line analysis
* Authentication analysis
* Source and destination IP analysis
* User and host investigation
* Windows Security Event analysis
* KQL-based threat hunting
* Event correlation
* MITRE ATT&CK mapping
* Detection tuning
* Incident documentation

---


# 🤖 SOAR — Automated RDP Brute Force Response

The project includes a **SOAR workflow** built around **Detection Rule 5**.

```text
RDP Brute Force
      ↓
4625 Failed Logons
      ↓
4624 Successful Logon
      ↓
Sentinel Detection Rule 5
      ↓
Microsoft Sentinel Incident
      ↓
SOAR Playbook
      ↓
Extract IP + Account + Host
      ↓
Analyst Approval
      ↓
Automated Containment
      ├── Disable AD Account
      ├── Block Attacker IP
      └── Update Incident
```

The playbook implements a **Human-in-the-Loop** approval step before disruptive containment actions are performed.

### Automated Response

* Disable the compromised Active Directory account
* Block the attacker IP using Windows Firewall
* Update the Sentinel incident
* Document the response
* Resolve the incident after successful containment

The remediation workflow was validated directly on the target system.

---


# 🎯 Project Objectives

* Simulate a realistic multi-stage attack
* Generate and investigate Windows security telemetry
* Build custom Microsoft Sentinel detections
* Investigate endpoint activity using Defender for Endpoint
* Correlate security events using KQL
* Map attacks to MITRE ATT&CK
* Implement automated incident response using SOAR
* Practice SOC Tier 1 investigation methodology
* Document the complete attack and response lifecycle

---

# 📁 Repository Structure

```text
SOC-Microsoft-Defender-Lab/
│
├── README.md
├── Soar-Playbook.md
│
├── Analytics-Rules/
│   ├── 01-analytic-rule-port-scan.md
│   ├── 02-analytic-rule-discovery.md
│   ├── 03-analytic-rule-defense-evasion.md
│   ├── 04-analytic-rule-schedule-task.md
│   └── 05-analytic-rule-brute-force.md
│
├── Attack Chain/
│   ├── 01-reconnaissance-port-scan.md
│   ├── 02-rdp-brute-force.md
│   ├── 03-discovery.md
│   ├── 04-privilege-escalation.md
│   ├── 05-persistence-scheduled-task.md
│   ├── 06-lateral-movement.md
│   ├── 07-domain-compromise.md
│   ├── 08-defense-evasion.md
│   └── 09-data-exfiltration.md
│
├── images/
│   ├── analytic-rules/
│   ├── data-exfiltration/
│   ├── defense-evasion/
│   ├── discovery/
│   ├── domain-compromise/
│   ├── lateral-movement/
│   ├── persistence/
│   ├── privilege-escalation/
│   ├── rdp-brute-force/
│   ├── reconnaissance-port-scan/
│   └── soar-playbook-rdp-brute-force/
    
```

---

# 🚀 Final Outcome

The project combines **attack simulation, EDR investigation, SIEM detection engineering, KQL, MITRE ATT&CK, and SOAR-based automated response** in a controlled home lab environment.

> **Lab Scope:** All attack activity was performed in an isolated environment for defensive security research and SOC training.
