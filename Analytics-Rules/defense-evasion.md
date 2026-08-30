# 📄 Detection Rule 3: Windows Security Event Log Cleared

## 📌 Overview

- **Rule Name:** Windows Security Event Log Cleared
- **Severity:** High
- **MITRE ATT&CK:** Defense Evasion → Indicator Removal: Clear Windows Event Logs (`T1070.001`)
- **Data Source:** Windows `SecurityEvent` — Event ID `1102`
- **Target Entities:** `Computer`, `Account`

## 📝 Description

This Microsoft Sentinel Analytic Rule detects when the Windows Security Event Log is cleared.

Event ID `1102` is generated when the Security audit log is cleared. Attackers may perform this action to remove evidence of previous activity and evade detection.

## 💻 KQL Query

```kql
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity
````

## 🎯 Entity Mapping

* **Host:** `Computer`
* **Account:** `Account`

## ⚙️ Analytic Rule Configuration

![Windows Security Event Log Cleared - Rule Configuration](../images/analytic-rules/03-analytic-rule-defence-evasion-config.png)

## 🔎 Detection Logic

```text
Windows Security Event Log
          ↓
       Event ID 1102
          ↓
     Log Cleared
          ↓
 Microsoft Sentinel Alert
          ↓
   SOC Investigation
```

## 🚨 Detection Result

The rule successfully detected a Windows Security Event Log clearing activity on the Domain Controller.

* **Computer:** `DC-01.mylab.local`
* **Event ID:** `1102`
* **Severity:** High
* **MITRE ATT&CK:** `T1070.001`
* **Detection Source:** Microsoft Sentinel

![Windows Security Event Log Cleared - Sentinel Incident](../images/analytic-rules/03-analytic-rule-defence-evasion-incident.png)

## 🛡️ MITRE ATT&CK

### T1070.001 — Clear Windows Event Logs

* **Tactic:** Defense Evasion
* **Technique:** Indicator Removal: Clear Windows Event Logs

Clearing Windows event logs can remove forensic evidence and hinder SOC investigations.

> **Lab Scope:** Developed and tested in an isolated SOC home lab for defensive security research and SOC Tier 1 training.

```
```
