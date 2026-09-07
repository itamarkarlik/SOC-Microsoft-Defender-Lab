# 🚨 Detection Rule 5: Suspicious RDP Brute Force Attempt with Success Validation

## 📌 Overview

* **Rule Name:** Suspicious RDP Brute Force Attempt with Success Validation
* **Severity:** Medium
* **MITRE ATT&CK:** Credential Access → Brute Force: Password Guessing (`T1110.001`)
* **Entities:** Source IP (`IpAddress`), Host (`Computer`), Account (`CompromisedAccounts`)

## 📝 Description

This Microsoft Sentinel Analytic Rule detects suspicious RDP brute-force activity and validates whether the attack was followed by a successful authentication.

It monitors Windows Security Event Log events:

* **4625** — An account failed to log on
* **4624** — An account was successfully logged on

The rule focuses on network-based authentication activity using:

* **Logon Type 3** — Network Logon
* **Logon Type 10** — Remote Interactive Logon, commonly associated with RDP

The rule triggers when **5 or more failed authentication attempts occur within 5 minutes** from the same source IP against the same host.

It then correlates the failed authentication attempts with successful logons from the same source IP and destination host. If a successful authentication occurs after the failed attempts, the `IsSuccessfulBruteForce` field is set to `true`.

This correlation helps SOC analysts distinguish repeated failed authentication activity from a potential successful account compromise.

## 💻 KQL Query

```kql
let timeframe = 5m;
let threshold = 5;

let FailedLogons = 
    SecurityEvent
    | where TimeGenerated >= ago(timeframe)
    | where EventID == 4625
    | where LogonType in (3, 10)
    | where IpAddress !in ("-", "127.0.0.1", "::1")
    | summarize 
        FailedAttempts = count(),
        FailedUsers = make_set(TargetUserName),
        FirstFailedAttempt = min(TimeGenerated),
        LastFailedAttempt = max(TimeGenerated)
        by IpAddress, Computer
    | where FailedAttempts >= threshold;

let SuccessfulLogons = 
    SecurityEvent
    | where TimeGenerated >= ago(timeframe)
    | where EventID == 4624
    | where LogonType in (3, 10)
    | where IpAddress !in ("-", "127.0.0.1", "::1")
    | summarize 
        SuccessfulAttempts = count(),
        SuccessfulUsers = make_set(TargetUserName),
        FirstSuccessAttempt = min(TimeGenerated)
        by IpAddress, Computer;

FailedLogons
| join kind=leftouter (SuccessfulLogons) on IpAddress, Computer
| extend IsSuccessfulBruteForce =
    iff(
        isnotnull(SuccessfulAttempts)
        and FirstSuccessAttempt >= FirstFailedAttempt,
        true,
        false
    )
| project 
    Computer,
    IpAddress,
    FailedAttempts,
    FailedUsers,
    IsSuccessfulBruteForce,
    SuccessfulAttempts = coalesce(SuccessfulAttempts, 0),
    CompromisedAccounts =
        iff(IsSuccessfulBruteForce, SuccessfulUsers, dynamic([])),
    FirstFailedAttempt,
    LastFailedAttempt,
    FirstSuccessAttempt
```

## ⚙️ Detection Tuning

Potential false positives include legitimate users entering incorrect credentials repeatedly, automated services using outdated credentials, or administrative activity involving repeated RDP authentication attempts.

The threshold of **5 failed attempts within 5 minutes** helps reduce noise while still identifying potentially aggressive password-guessing activity.


### 📸 Analytic Rule Configuration

![RDP Brute Force Analytic Rule Configuration](../images/analytic-rules/05-analytic-rule-brute-force-config.png)

## 🚨 Detection Result

The rule successfully detected suspicious RDP brute-force activity from `192.168.10.133` against the Domain Controller `DC-01.mylab.local`, followed by a successful authentication to the `Jsmith` account.

The generated Microsoft Sentinel incident contained:

* **Source IP:** `192.168.10.133`
* **Target Host:** `DC-01.mylab.local`
* **Target Account:** `Jsmith`
* **Failed Attempts:** `6`
* **Successful Attempts:** `1`
* **Successful Brute Force:** `true`
* **Severity:** Medium
* **MITRE ATT&CK Technique:** `T1110.001`

### 📸 Sentinel Incident

![RDP Brute Force Sentinel Incident](../images/analytic-rules/05-analytic-rule-brute-force-incident.png)

## 🛡️ MITRE ATT&CK Mapping

### T1110.001 — Password Guessing

* **Tactic:** Credential Access
* **Technique:** Brute Force: Password Guessing

The detection identifies repeated authentication failures and validates whether the activity was followed by a successful authentication, helping SOC analysts prioritize potential account compromise.
