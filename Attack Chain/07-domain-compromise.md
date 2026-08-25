# 07 — Domain Compromise

## Domain Compromise via Backdoor Account Creation

After establishing a remote session on the Domain Controller `ADDC` (`192.168.10.130`) via WinRM, post-exploitation activity was performed to establish domain-level persistence.

The activity was executed directly on the Domain Controller under the remote context of:

```text
MYLAB\Jsmith
```

---

## 1. Domain User Creation & Privilege Escalation

A new domain user account was created and added to the `Domain Admins` group:

```powershell
net user EvilAdmin P@ssword123! /add /domain
net group "Domain Admins" EvilAdmin /add /domain
```

Group membership was then verified:

```powershell
net group "Domain Admins" /domain
```

The output confirmed that `EvilAdmin` was successfully added to the `Domain Admins` group alongside the existing administrators.

![Attacker - Domain Compromise](../images/domain-compromise/attacker-domain-compromise.png)

This demonstrated successful creation of a privileged domain account and establishment of domain-level persistence.

---

## 2. Microsoft Defender for Endpoint Investigation

Microsoft Defender for Endpoint recorded the activity on the Domain Controller.

The telemetry showed `wsmprovhost.exe` invoking `net.exe` to create the `EvilAdmin` domain account and modify group membership.

Relevant events included:

```text
T1136.002 — Domain Account
T1098 — Account Manipulation
T1087 — Account Discovery
```

Defender also generated detections for suspicious account creation and anomalous account activity.

![EDR - Domain Compromise](../images/domain-compromise/edr-domain-compromise.png)

The process activity confirmed the relationship between the remote PowerShell session, `wsmprovhost.exe`, and the `net.exe` / `net1.exe` commands used to modify Active Directory.

![EDR - Domain Compromise Alert](../images/domain-compromise/edr-alert-domain-compromise.png)

---

## 3. Microsoft Sentinel Investigation

Microsoft Sentinel was used to correlate the Windows Security events generated during the account creation and privilege assignment.

The investigation identified:

```text
Event ID: 4720 — A user account was created
Event ID: 4728 — A member was added to a security-enabled global group
Target Account: EvilAdmin
Group Name: Domain Admins
```

The events showed `Jsmith` as the account performing the activity and `EvilAdmin` as the newly created privileged account.

![Microsoft Sentinel - Domain Compromise](../images/domain-compromise/sentinel-domain-compromise.png)

The Sentinel query provided additional confirmation that the new account was created and subsequently added to the `Domain Admins` group.

---

## 4. MITRE ATT&CK Mapping

The activity was mapped to the following MITRE ATT&CK techniques:

### T1136.002 — Create Account: Domain Account

**Tactic:** Persistence

**Technique:** Create Account — Domain Account

### T1098 — Account Manipulation

**Tactic:** Persistence, Privilege Escalation

**Technique:** Account Manipulation

---

> **Lab Scope:** All activity was performed within the isolated SOC home lab environment for defensive security research and SOC Tier 1 training.
