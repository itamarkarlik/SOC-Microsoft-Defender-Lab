# 📄 Detection Rule 2: Suspicious Discovery Commands Executed

## 📌 Overview

* **Rule Name:** Suspicious Discovery Commands Executed
* **Severity:** Medium
* **MITRE ATT&CK:** Discovery → System Information Discovery (`T1082`), Account Discovery (`T1087`)
* **Entities:** Host (`Computer`), Account (`Account`)

## 📝 Description

This Microsoft Sentinel Analytic Rule detects multiple Windows discovery commands executed rapidly by the same user on the same host.

It monitors Windows process creation events:

* **4688** — A new process has been created

The rule monitors the following discovery tools:

* `whoami.exe`
* `net.exe`
* `net1.exe`
* `ipconfig.exe`
* `systeminfo.exe`
* `nltest.exe`

The rule triggers when the same account executes **2 or more distinct discovery tools within a 5-minute window** on the same computer.

This detection helps identify rapid system and account discovery activity that may indicate an attacker gathering information about the compromised host or domain environment.

## 💻 KQL Query

```kql
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4688
| extend ProcessName = tolower(tostring(parse_path(NewProcessName).Filename))
| where ProcessName in ("whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "nltest.exe")
| summarize ExecutedCommandsCount = dcount(ProcessName),
            CommandList = make_set(ProcessName)
    by Account, Computer, bin(TimeGenerated, 5m)
| where ExecutedCommandsCount >= 2
| project TimeGenerated, Computer, Account, ExecutedCommandsCount, CommandList
```

## ⚙️ Detection Tuning

Potential false positives include legitimate administrative troubleshooting,
system inventory scripts, and IT support activity.

### 📸 Analytic Rule Configuration

![Suspicious Discovery Commands Analytic Rule Configuration](../images/analytic-rules/02-analytic-rule-discovery-config.png)


## 🚨 Detection Result

The rule successfully detected multiple discovery commands executed by `MYLAB\Administrator` on the Domain Controller `DC-01.mylab.local`.

The generated Microsoft Sentinel incident contained:

* **Account:** `MYLAB\Administrator`
* **Computer:** `DC-01.mylab.local`
* **Detection Time:** August 28, 2026 at 4:25 PM
* **Commands Detected:** `ipconfig.exe`, `whoami.exe`, `net.exe`, `net1.exe`, `systeminfo.exe`
* **Distinct Commands:** `5`
* **Severity:** Medium

### 📸 Sentinel Incident

![Suspicious Discovery Commands Sentinel Incident](../images/analytic-rules/02-analytic-rule-discovery-incident.png)

## 🛡️ MITRE ATT&CK Mapping

### T1082 — System Information Discovery

* **Tactic:** Discovery
* **Technique:** System Information Discovery

### T1087 — Account Discovery

* **Tactic:** Discovery
* **Technique:** Account Discovery

