# 🚨 Detection Rule 5: Suspicious RDP Brute Force Attempt with Success Validation

## 📌 Overview

- **Rule Name:** Suspicious RDP Brute Force Attempt with Success Validation
- **Severity:** Medium
- **MITRE ATT&CK:** Credential Access → Brute Force (`T1110.001`)
- **Data Source:** Windows `SecurityEvent`
- **Event IDs:** `4625` (Failed Logon), `4624` (Successful Logon)
- **Target Entities:** `IpAddress`, `Computer`, `CompromisedAccounts`

## 📝 Description

This Microsoft Sentinel Analytic Rule detects RDP brute-force activity and validates whether the attack resulted in a successful login.

The rule identifies multiple failed authentication attempts from the same source IP and correlates them with a subsequent successful logon from that source.

The detection triggers when **5 or more failed attempts** occur within **5 minutes**, with support for RDP `LogonType 10`.

## 🔍 Detection Logic

1. Detect failed logons using Event ID `4625`.
2. Filter for `LogonType 3` and `10`.
3. Trigger when there are **≥ 5 failed attempts** from the same IP.
4. Search for successful logons using Event ID `4624`.
5. Correlate the failed and successful activity by `IpAddress` and `Computer`.
6. Set `IsSuccessfulBruteForce` to `true` when a successful logon occurs after the failed attempts.

## 💻 KQL Query

```kusto
let timeframe = 5m;
let threshold = 5;

// 1. Collect Failed Logon Attempts
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

// 2. Collect Successful Logons
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

// 3. Correlate Failures & Successes
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
````

## ⚙️ Analytic Rule Configuration

| Parameter           | Setting                                                    |
| ------------------- | ---------------------------------------------------------- |
| **Rule Name**       | Suspicious RDP Brute Force Attempt with Success Validation |
| **Severity**        | Medium                                                     |
| **Tactic**          | Credential Access                                          |
| **Technique**       | T1110.001 - Password Guessing                              |
| **Schedule**        | Every 5 minutes                                            |
| **Lookup Window**   | Last 5 minutes                                             |
| **Alert Threshold** | Results > 0                                                |

## 🎯 Entity Mapping

* **IP Address:** `IpAddress` → `Address`
* **Host:** `Computer` → `HostName`
* **Account:** `CompromisedAccounts` → `Name`

## ⚙️ Analytic Rule Configuration

![RDP Brute Force Analytic Rule Configuration](../images/analytic-rules/05-analytic-rule-brute-force-config.png)

## 🚨 Detection Result

The rule successfully detected suspicious RDP brute-force activity followed by a successful authentication.

* **Source IP:** `192.168.10.133`
* **Target Host:** `DC-01.mylab.local`
* **Target Account:** `Jsmith`
* **Failed Attempts:** `6`
* **Successful Brute Force:** `true`
* **Successful Attempts:** `1`
* **MITRE ATT&CK:** `T1110.001`

![RDP Brute Force Sentinel Incident](../images/analytic-rules/05-analytic-rule-brute-force-incident.png)

## 🛡️ MITRE ATT&CK

### T1110.001 — Password Guessing

* **Tactic:** Credential Access
* **Technique:** Brute Force: Password Guessing

The detection identifies repeated authentication failures and validates whether the activity was followed by a successful authentication, helping SOC analysts prioritize potential account compromise.

> **Lab Scope:** Developed and tested in an isolated SOC home lab for defensive security research and SOC Tier 1 training.

```
```
