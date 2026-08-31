
# 📄 Detection Rule 4: Scheduled Task Created

## 📌 Overview

- **Rule Name:** Scheduled Task Created
- **Severity:** Medium
- **MITRE ATT&CK:** Persistence → Scheduled Task/Job: Scheduled Task (`T1053.005`)
- **Data Source:** Windows `SecurityEvent` — Event ID `4698`
- **Target Entities:** `Computer`, `Account`

## 📝 Description

This Microsoft Sentinel Analytic Rule detects the creation of new scheduled tasks on Windows endpoints.

Scheduled Tasks are commonly abused by attackers to establish **persistence** or execute malicious programs automatically at predefined times or during system startup.

## 💻 KQL Query

```kql
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4698
| extend TaskName = parse_xml(EventData).EventData.Data[0].["#text"]
| project TimeGenerated, Computer, Account, TaskName, Activity
````

## 🎯 Entity Mapping

* **Host:** `Computer`
* **Account:** `Account`

## ⚙️ Analytic Rule Configuration

![Scheduled Task Analytic Rule Configuration](../images/analytic-rules/04-analytic-rule-schedule-task-config.png)

## 🔎 Detection Logic

```text
Windows Scheduled Task Created
          ↓
       Event ID 4698
          ↓
   Extract Task Name
          ↓
 Microsoft Sentinel Alert
          ↓
   SOC Investigation
```

## 🚨 Detection Result

The rule successfully detected the creation of a new scheduled task.

* **Computer:** `DC-01.mylab.local`
* **Account:** `MYLAB\Administrator`
* **Task Name:** `\WindowsUpdateCheck`
* **Event ID:** `4698`
* **Severity:** Medium
* **MITRE ATT&CK:** `T1053.005`

![Scheduled Task Sentinel Incident](../images/analytic-rules/04-analytic-rule-schedule-task-incident.png)

## 🛡️ MITRE ATT&CK

### T1053.005 — Scheduled Task

* **Tactic:** Persistence
* **Technique:** Scheduled Task/Job: Scheduled Task

Attackers can create scheduled tasks to maintain persistence or execute commands automatically on compromised systems.

> **Lab Scope:** Developed and tested in an isolated SOC home lab for defensive security research and SOC Tier 1 training.

```
```
