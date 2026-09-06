# 08 — Defense Evasion

## Clearing Windows Security Event Logs

In an attempt to disrupt SOC forensic analysis and remove historical security evidence, the attacker cleared the Windows Security Event Log on the Domain Controller (`DC-01`).

The activity was performed remotely through WinRM using the compromised domain account:

```text
MYLAB\Jsmith
```

### Event Log Cleared via Command Line

The attacker used `wevtutil.exe` through the established PowerShell Remoting session to clear the Security event log:

```powershell
wevtutil cl Security
```

The attacker then verified the remaining Security events:

```powershell
Get-EventLog -LogName Security -Newest 5
```

![Attacker cleared Windows Security Event Log](../images/defence-evasion/attacker-defence-evasion.png)

### Microsoft Defender for Endpoint

Microsoft Defender for Endpoint detected the execution of `wevtutil.exe` and recorded the Security event log clearing activity.


![Microsoft Defender for Endpoint - Clear Windows Event Logs](../images/defence-evasion/edr-defence-evasion.png)

### Microsoft Sentinel

Microsoft Sentinel was used to investigate the Windows Security Event Log clearing activity.

Windows generated **Event ID 1102 — The audit log was cleared**, allowing the activity to be identified even after the local Security log was cleared.

The relevant event was associated with `DC-01.mylab.local`.

![Microsoft Sentinel - Event ID 1102](../images/defence-evasion/sentinel-defence-evasion.png)

### MITRE ATT&CK

* **T1070.001 — Clear Windows Event Logs**

### Detection Summary

The defense evasion activity was successfully detected and validated across **Microsoft Defender for Endpoint and Microsoft Sentinel**. Defender recorded the execution of `wevtutil.exe` through the `wsmprovhost.exe` remote session, while Sentinel confirmed the log-clearing activity through **Event ID 1102**. The combination of remote PowerShell execution, `wevtutil.exe`, and Event ID `1102` provided strong evidence of intentional Security Event Log clearing.
