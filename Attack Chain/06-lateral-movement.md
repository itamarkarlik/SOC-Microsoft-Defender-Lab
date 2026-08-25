# 06 — Lateral Movement

## Remote Session via WinRM & PowerShell Remoting

After establishing persistent access on `TARGET-PC` (`192.168.10.132`), lateral movement was performed toward the Domain Controller `ADDC` (`192.168.10.130`) using **Windows Remote Management (WinRM)** and **PowerShell Remoting**.

The activity was performed under the context of the compromised domain user:

```text
MYLAB\Jsmith
```

---

## 1. Host Reachability & Port Verification

Network connectivity and WinRM service availability on the Domain Controller were verified from `TARGET-PC`.

```powershell
Test-NetConnection -ComputerName 192.168.10.130 -Port 5985
```

The output confirmed that **TCP port 5985** was open and accessible.

### Port Information

| Port   | Protocol | Service      |
| ------ | -------- | ------------ |
| `5985` | TCP      | WinRM / HTTP |

---

## 2. Establishing the Remote Session

An interactive PowerShell Remoting session was established from `TARGET-PC` to the Domain Controller:

```powershell
Enter-PSSession -ComputerName 192.168.10.130 -Credential (Get-Credential)
```

The compromised domain credentials were supplied:

```text
Jsmith@mylab.local
```

A successful remote PowerShell session was established on the Domain Controller.

Example remote prompt:

```text
[192.168.10.130]: PS C:\Users\Jsmith\Documents>
```

This confirmed that the PowerShell session was executing remotely on `ADDC`.

---

## 4. Target Host Verification

The remote execution context was verified using:

```powershell
hostname
whoami
```

The output confirmed:

* Target host: `ADDC`
* User context: `MYLAB\Jsmith`

This demonstrated successful remote command execution on the Domain Controller.

---

## 5. Microsoft Defender for Endpoint Investigation

Microsoft Defender for Endpoint was used to investigate the lateral movement activity across both endpoints.

Relevant telemetry included:

* PowerShell process execution
* Process lineage
* Network connections
* TCP connection to port `5985`
* WinRM activity
* `wsmprovhost.exe` execution on the Domain Controller
* User and device information
* Device timeline activity

### Relevant Process / Network Activity

On `TARGET-PC`, the investigation focused on PowerShell activity and the outbound connection to:

```text
192.168.10.130:5985
```

On `ADDC`, the investigation included the corresponding WinRM server-side activity, including:

```text
wsmprovhost.exe
```

The activity demonstrated the relationship between the source endpoint and the Domain Controller.

---

## 6. MITRE ATT&CK Mapping

The activity was mapped to:

### T1021.006 — Windows Remote Management

**Tactic:** Lateral Movement

**Technique:** Remote Services: Windows Remote Management

The technique describes the use of Windows Remote Management (WinRM) to execute commands remotely on another Windows system.

---

## 7. Microsoft Sentinel Investigation

Microsoft Sentinel was used to correlate endpoint, authentication, and network telemetry associated with the remote session.

Relevant investigation data included:

* Device network activity
* Process execution
* Windows authentication events
* Source and destination IP addresses
* User account
* Remote logon activity

### Authentication Evidence

Windows Event ID `4624` was investigated to identify successful network logon activity.

The investigation focused on:

```text
Event ID: 4624
Logon Type: 3
Account: MYLAB\Jsmith
Source: TARGET-PC
Destination: ADDC
```

This provided additional evidence supporting the remote access activity.

---



> **Lab Scope:** All activity was performed within the isolated SOC home lab environment for defensive security research and SOC Tier 1 training.
