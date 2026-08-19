# 04 — Privilege Escalation

## Unquoted Service Path

After gaining RDP access to the victim machine as `MYLAB\Jsmith`, the attacker proceeded with local discovery to identify potential privilege escalation opportunities.

### 1. Service Enumeration

From the compromised `Jsmith` session, Windows services were enumerated to identify potentially misconfigured services.

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i /v "c:\windows\" | findstr /i /v """
```

The enumeration revealed a suspicious service named `VulnerableApp` with the following executable path:

```text
C:\Program Files\Custom Software\App Service\service.exe
```

The path contained multiple spaces and was not enclosed in quotation marks.

### 2. Service Configuration Analysis

The service configuration was examined to determine how it was executed:

```cmd
sc.exe qc VulnerableApp
```

The service was configured with:

* **Start Type:** `AUTO_START`
* **Service Account:** `LocalSystem`
* **Binary Path:** `C:\Program Files\Custom Software\App Service\service.exe`

![Service Discovery](../images/privesc/attacker-service-discovery.png)

The service was a pre-existing application service created by the Administrator during the lab setup. The service was intentionally configured with an **Unquoted Service Path** and insecure directory permissions to simulate an enterprise misconfiguration.

### 3. Permission Analysis

The attacker then inspected the permissions on the application directory:

```cmd
icacls "C:\Program Files\Custom Software"
```

The results showed that the `Users` group had write permissions on the directory.

This was significant because the service path contained spaces and the attacker could write to one of the directories involved in the path resolution.

![Service Permissions](../images/privesc/attacker-service-permissions.png)

### 4. Payload Transfer

A controlled payload was prepared on the Kali attacker machine and transferred to the compromised endpoint through the existing RDP session.

The payload was downloaded to:

```text
C:\Users\Jsmith\Desktop\App.exe
```

### 5. Service Path Hijacking

The payload was then placed at the path that could be resolved before the legitimate service executable:

```text
C:\Program Files\Custom Software\App.exe
```

This exploited the combination of:

* Unquoted service path
* Spaces in the executable path
* Writable application directory
* `LocalSystem` service execution

### 6. Triggering the Exploitation

`Jsmith` did not have permission to manually start or stop the service.

Because `VulnerableApp` was configured as `AUTO_START`, the system was restarted to trigger the service.
During system startup, the service executed under the `LocalSystem` context.

### 7. Privilege Escalation Verification

After the system restarted, the local Administrators group was checked:

```cmd
net localgroup Administrators
```

The result confirmed that `Jsmith` had been successfully added to the local `Administrators` group.

![Privilege Escalation Result](../images/privesc/privilege-escalation-result.png)

### 8. Defender for Endpoint

Microsoft Defender for Endpoint was investigated for evidence of the privilege escalation chain.

The investigation focused on the process execution originating from the Windows service and the subsequent activity performed under the elevated context.

![Defender Privilege Escalation](../images/privesc/edr-privesc.png)

### 9. Sentinel Investigation

Microsoft Sentinel was used to investigate the corresponding Windows Security events.

The primary event of interest was:

* **Event ID 4732 — A member was added to a security-enabled local group**

The event was used to confirm the addition of `Jsmith` to the local `Administrators` group.

```kql
SecurityEvent
| where EventID == 4732
| where Computer contains "target-pc"
| project TimeGenerated, Computer, Activity, EventData, SubjectUserName
| sort by TimeGenerated desc
```

![Sentinel Privilege Escalation](../images/privesc/sentinel-privesc.png)

### 10. MITRE ATT&CK

The activity was associated with:

* **T1068 — Exploitation for Privilege Escalation**
* **T1098.001 — Account Manipulation: Additional Local or Domain Groups**

### 11. Result

The attack chain successfully progressed from the compromised `Jsmith` account to local administrative privileges:

```text
RDP Access
    ↓
Jsmith
    ↓
Service Enumeration
    ↓
Unquoted Service Path Identified
    ↓
Writable Application Directory
    ↓
Service Path Hijacking
    ↓
LocalSystem Execution
    ↓
Jsmith Added to Local Administrators
```

This demonstrated how a misconfigured Windows service can provide a privilege escalation path for a compromised standard user.
