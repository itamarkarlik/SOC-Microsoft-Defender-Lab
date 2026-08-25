# 06 — Lateral Movement

## Remote Session via WinRM & PowerShell Remoting

After establishing persistent access on `TARGET-PC` (`192.168.10.132`), lateral movement was performed toward the Domain Controller `ADDC` (`192.168.10.130`) using **Windows Remote Management (WinRM)** and **PowerShell Remoting**.

The activity was performed under the context of:

```text
MYLAB\Jsmith
```

---

## 1. Host Reachability & Port Verification

Network connectivity and WinRM availability were verified from `TARGET-PC`:

```powershell
Test-NetConnection -ComputerName 192.168.10.130 -Port 5985
```

The test confirmed successful connectivity to TCP port `5985`.

| Port   | Protocol | Service      |
| ------ | -------- | ------------ |
| `5985` | TCP      | WinRM / HTTP |



---

## 2. Establishing the Remote Session

A remote PowerShell session was established using:

```powershell
Enter-PSSession -ComputerName 192.168.10.130 -Credential (Get-Credential)
```

The compromised domain credentials were supplied:

```text
Jsmith@mylab.local
```

The successful remote prompt confirmed execution on the Domain Controller:

```text
[192.168.10.130]: PS C:\Users\Jsmith\Documents>
```

The remote context was verified with:

```powershell
whoami
hostname
```

The output confirmed:

```text
MYLAB\Jsmith
DC-01
```
![Attacker - WinRM Connectivity](../images/lateral-movement/attacker-lateral-movement.png)

---

## 3. Microsoft Defender for Endpoint Investigation

Microsoft Defender for Endpoint provided telemetry from both sides of the lateral movement.

On `TARGET-PC`, Defender recorded PowerShell activity and the outbound WinRM connection:

```text
192.168.10.132 → 192.168.10.130:5985
```

The event was mapped to:

```text
T1021.006 — Windows Remote Management
T1071.001 — Web Protocols
```

![EDR - TARGET-PC Lateral Movement](../images/lateral-movement/edr-targetpc-lateral-movement.png)

On the receiving host, Defender recorded `wsmprovhost.exe` creating processes such as:

```text
whoami.exe
hostname.exe
ipconfig.exe
```

This provided evidence of remote command execution and subsequent system/network discovery.

![EDR - DC01 Lateral Movement](../images/lateral-movement/edr-dc01-lateral-movement.png)

The corresponding WinRM network connection was also observed on the Domain Controller:

```text
192.168.10.132:60278 → 192.168.10.130:5985
```

![EDR - DC01 WinRM Connection](../images/lateral-movement/edr-dc01-connection-lateral-movement.png)

---

## 4. Discovery Activity

Following the remote session, `wsmprovhost.exe` executed discovery commands under the `MYLAB\Jsmith` context.

Observed activity included:

```text
whoami.exe
hostname.exe
ipconfig.exe
```

Defender mapped the discovery activity to:

```text
T1082 — System Information Discovery
T1016 — System Network Configuration Discovery
```

This demonstrated that the remote session was used not only for access, but also for system and network discovery.

---

## 5. Microsoft Sentinel Investigation

Microsoft Sentinel was used to correlate the endpoint and authentication telemetry.

The investigation focused on successful Windows network logons:

```text
Event ID: 4624
Logon Type: 3
Account: Jsmith
```

The query returned successful network logon activity associated with `Jsmith`, including activity involving the Domain Controller.

![Microsoft Sentinel - Successful Logon](../images/lateral-movement/sentinel-login-lateral-movement.png)

This provided additional authentication evidence supporting the lateral movement investigation.

---

## 6. MITRE ATT&CK Mapping

The primary lateral movement technique was:

### T1021.006 — Windows Remote Management

**Tactic:** Lateral Movement

**Technique:** Remote Services: Windows Remote Management

Additional observed techniques included:

* `T1082` — System Information Discovery
* `T1016` — System Network Configuration Discovery
* `T1071.001` — Web Protocols

---

> **Lab Scope:** All activity was performed within the isolated SOC home lab environment for defensive security research and SOC Tier 1 training.
