
# 08 — Defense Evasion

## Clearing Windows Security Event Logs

In an attempt to disrupt SOC forensic analysis and hide post-exploitation activity, the attacker executed commands to clear the Windows Security log on the Domain Controller (`DC-01`).

The evasion activity was executed remotely via WinRM under the context of:

```text
MYLAB\Jsmith

```

---

## 1. Event Log Cleared via Command Line

The attacker utilized the built-in Windows utility `wevtutil.exe` over the established PowerShell Remote session to clear the Security log:

```powershell
wevtutil cl Security

```

Verification was performed immediately using `Get-EventLog`:

```powershell
Get-EventLog -LogName Security -Newest 5

```

The output confirmed that historical security logs were wiped, leaving only fresh system events generated post-clearing.

---

## 2. Microsoft Defender for Endpoint Investigation

Microsoft Defender for Endpoint generated a high-severity telemetry event upon detecting the execution of `wevtutil.exe` spawned by the WinRM worker process (`wsmprovhost.exe`).

Key EDR observations included:

* **Activity:** `wsmprovhost.exe cleared the Security event log`
* **Process Image:** `C:\Windows\System32\wevtutil.exe`
* **User Context:** `MYLAB\jsmith`
* **Action Type:** `EventLogWasCleared`

The activity was mapped directly to MITRE ATT&CK:

```text
T1070.001 — Indicator Removal on Host: Clear Windows Event Logs

```

---

## 3. Microsoft Sentinel Investigation

Although the local log was cleared, the log clearing action itself generated a critical Windows audit event before deletion completed.

Microsoft Sentinel ingested the event via Azure Monitor Agent (AMA), allowing analysts to identify the log clearing attempt using KQL:

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer contains "dc-01"
| where EventID == 1102
| project TimeGenerated, Computer, EventID, Activity, SubjectUserName

```

The query returned:

* **Event ID:** `1102` (*The audit log was cleared*)
* **Computer:** `DC-01.mylab.local`
* **SubjectUserName:** `Jsmith`

This verified that SIEM log ingestion preserves forensic evidence of anti-forensic techniques.

---

## 4. MITRE ATT&CK Mapping

### T1070.001 — Clear Windows Event Logs

**Tactic:** Defense Evasion

**Technique:** Indicator Removal on Host: Clear Windows Event Logs

---

> **Lab Scope:** All activity was performed within the isolated SOC home lab environment for defensive security research and SOC Tier 1 training.
