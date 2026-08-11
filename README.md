# SOC Home Lab — Microsoft Defender XDR, EDR & Sentinel

A hands-on **SOC / Blue Team Home Lab** designed to simulate a small enterprise environment, generate controlled security attacks, and investigate them using Microsoft's security stack.

The primary goal of this project is to practice the complete SOC investigation workflow — from **attack simulation and detection to investigation, correlation, MITRE ATT&CK mapping, and response**.

---

## 🏗️ Lab Architecture

```text
                         ┌──────────────────────────────────┐
                         │       MICROSOFT SECURITY           │
                         │                                  │
                         │  Microsoft Defender XDR           │
                         │  Microsoft Defender for Endpoint  │
                         │  Microsoft Sentinel               │
                         └───────────────┬──────────────────┘
                                         │
                         Monitoring / Detection
                                         │
                         ┌───────────────┴───────────────┐
                         │                               │
                         ▼                               ▼
              ┌──────────────────┐             ┌──────────────────┐
              │    TARGET-PC     │             │      ADDC        │
              │    Windows 10    │             │ Windows Server   │
              │                  │             │ Active Directory │
              │ 192.168.10.132   │             │ 192.168.10.130   │
              └────────┬─────────┘             └────────┬─────────┘
                       │                                │
                       │         Domain / Network       │
                       └───────────────┬────────────────┘
                                       │
                                       │
                              ┌────────▼────────┐
                              │   KALI LINUX    │
                              │     ATTACKER     │
                              │                  │
                              │ 192.168.10.133   │
                              └──────────────────┘
```

---

## 🖥️ Lab Environment

| Host / Service                  | Role              | IP Address       | Platform       |
| ------------------------------- | ----------------- | ---------------- | -------------- |
| `KALI`                          | Attacker Machine  | `192.168.10.133` | Kali Linux     |
| `TARGET-PC`                     | Victim / Endpoint | `192.168.10.132` | Windows 10     |
| `ADDC`                          | Domain Controller | `192.168.10.130` | Windows Server |
| Microsoft Defender for Endpoint | EDR               | Cloud            | Microsoft      |
| Microsoft Defender XDR          | XDR Platform      | Cloud            | Microsoft      |
| Microsoft Sentinel              | SIEM              | Cloud            | Microsoft      |

---

# 🎯 Project Objectives

The main objectives of this lab are:

* Simulate controlled cyber attacks inside an isolated lab environment
* Generate security events on a Windows endpoint
* Detect malicious or suspicious activity using Microsoft Defender for Endpoint
* Investigate alerts and incidents using Microsoft Defender XDR
* Analyze security logs using Microsoft Sentinel
* Use KQL for security investigations
* Correlate activity between the endpoint, Active Directory, XDR and SIEM
* Map observed activity to **MITRE ATT&CK**
* Practice SOC Tier 1 investigation methodology
* Document findings and investigation procedures

---


# 🛡️ Security Stack

## Microsoft Defender for Endpoint — EDR

Microsoft Defender for Endpoint is used as the primary **Endpoint Detection and Response (EDR)** solution.

The investigation will focus on endpoint telemetry such as:

* Process execution
* Process trees
* Command lines
* Users
* Devices
* Files
* Network connections
* Security alerts
* Device timeline
* Detection and response actions

---

## Microsoft Defender XDR

Microsoft Defender XDR provides a broader security view and allows investigation and correlation of security signals.

The investigation workflow can include:

```text
Alert
  │
  ▼
Incident
  │
  ▼
Affected Device
  │
  ▼
User
  │
  ▼
Process / File / Network Activity
  │
  ▼
Related Alerts
  │
  ▼
MITRE ATT&CK Mapping
```

---

## Microsoft Sentinel — SIEM

Microsoft Sentinel is used for centralized security monitoring, log analysis, detection, and investigation.

**KQL (Kusto Query Language)** is used to query and investigate relevant security events.

Example workflow:

```text
Security Logs
     │
     ▼
   KQL Query
     │
     ▼
Suspicious Activity
     │
     ▼
   Correlation
     │
     ▼
Alert / Incident
     │
     ▼
 Investigation
     │
     ▼
   Response
```

---

# 🏢 Active Directory

The `ADDC` server acts as the **Active Directory Domain Controller** for the lab environment.

Active Directory provides the lab with realistic enterprise identity and authentication activity.

Relevant investigation areas may include:

* User authentication
* Failed logons
* Successful logons
* Account activity
* Domain authentication
* Privileged accounts
* Group membership
* Authentication anomalies
* Suspicious account activity

---

# ⚔️ Attack Scenarios

The lab will be gradually expanded with controlled attack scenarios.

Potential scenarios include:

* Brute-force authentication attempts
* Suspicious PowerShell activity
* Malicious file execution
* Network reconnaissance
* Host discovery
* Process discovery
* Account discovery
* Credential-related activity
* Persistence simulations
* Lateral movement simulations
* Active Directory attacks
* Suspicious command execution
* MITRE ATT&CK-based attack simulations

> **All attack activity is performed inside a controlled and isolated lab environment for defensive security research and SOC training.**

---

# 🔎 SOC Investigation Workflow

Each scenario will follow a structured SOC investigation process:

```text
┌─────────────────┐
│ Attack          │
│ Simulation      │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Detection       │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Alert Triage    │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Investigation   │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Log Correlation │
└────────┬────────┘
         ▼
┌─────────────────┐
│ MITRE ATT&CK    │
│ Mapping         │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Response        │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Documentation   │
└─────────────────┘
```

---

# 🧪 Investigation Documentation

For each attack scenario, the investigation will document relevant information such as:

* Date and time
* Source IP
* Destination IP
* Hostname
* Username
* Alert severity
* Detection source
* Process name
* Parent process
* Command line
* File path
* Network activity
* Related events
* MITRE ATT&CK technique
* Investigation findings
* Actions taken
* Final disposition

---

# 🗂️ Planned Repository Structure

```text
SOC-Home-Lab/
│
├── README.md
│
├── Architecture/
│   └── lab-architecture.png
│
├── Attack-Scenarios/
│   ├── Brute-Force/
│   ├── PowerShell/
│   ├── Network-Recon/
│   ├── Malware-Simulation/
│   └── Active-Directory/
│
├── Investigations/
│   ├── Incident-01/
│   ├── Incident-02/
│   └── Incident-03/
│
├── KQL/
│   ├── Authentication/
│   ├── Endpoint/
│   ├── Network/
│   └── Detection-Rules/
│
├── MITRE-ATT&CK/
│   └── Techniques.md
│
└── Screenshots/
    ├── Defender/
    ├── Sentinel/
    └── XDR/
```

---

# 📊 Technologies Used

| Category          | Technology                      |
| ----------------- | ------------------------------- |
| SIEM              | Microsoft Sentinel              |
| XDR               | Microsoft Defender XDR          |
| EDR               | Microsoft Defender for Endpoint |
| Identity          | Active Directory                |
| Query Language    | KQL                             |
| Attacker OS       | Kali Linux                      |
| Endpoint OS       | Windows 10                      |
| Domain Controller | Windows Server                  |
| Framework         | MITRE ATT&CK                    |

---

# 🚀 Future Improvements

The lab will be expanded over time to create a more complete enterprise-style SOC environment.

Planned improvements include:

* Additional Windows endpoints
* Additional Active Directory users and groups
* More attack scenarios
* More realistic authentication activity
* Advanced KQL investigations
* Custom Sentinel analytics rules
* Additional MITRE ATT&CK techniques
* Automated detection and response
* Advanced incident correlation
* Additional endpoint telemetry
* SOC investigation playbooks

---

# 📌 Current Lab Goal

The current environment serves as the foundation for a larger SOC laboratory.

The focus is not simply on performing attacks, but on understanding the **defensive investigation process**:

> **Attack → Detect → Triage → Investigate → Correlate → Map → Respond → Document**

This project is intended to demonstrate practical **SOC Tier 1 / Blue Team skills** in a controlled environment.
