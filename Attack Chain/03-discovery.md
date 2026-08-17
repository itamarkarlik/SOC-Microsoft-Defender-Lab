# 03 — Discovery

## System & Domain Discovery

After the reconnaissance phase, discovery activity was performed from the Windows endpoint to identify system information, user accounts, domain resources, and network shares.

### 1. System & Identity Discovery

The following commands were executed:

```cmd
hostname
systeminfo
whoami
whoami /groups
ipconfig /all
```

These commands identified the hostname, operating system, current user, group membership, and network configuration.

![System Identity Discovery](../images/discovery/attacker-system-identity-discovery.png)

![System Information Discovery](../images/discovery/attacker-system-information-discovery.png)

### 2. Domain & Account Discovery

Domain users and groups were enumerated using:

```cmd
net user /domain
net group /domain
```

The output revealed domain accounts and available domain groups.

![Domain Account Discovery](../images/discovery/attacker-domain-account-discovery.png)

### 3. Domain Controller Discovery

The Domain Controller was identified using:

```cmd
nltest /dsgetdc:MYLAB
```

The command identified `DC-01` at `192.168.10.130` as the Domain Controller for the `MYLAB` domain.

![Domain Controller Discovery](../images/discovery/attacker-domain-controller-discovery.png)

### 4. Network Share Discovery

Available network shares on the Domain Controller were enumerated using:

```cmd
net view \\DC-01
```

The results identified the `NETLOGON` and `SYSVOL` shares.

![Network Share Discovery](../images/discovery/attacker-network-share-discovery.png)

### 5. Defender for Endpoint

Microsoft Defender for Endpoint recorded the discovery activity, including execution of `systeminfo.exe`, `ipconfig.exe`, `ARP.EXE`, `net.exe`, and `nltest.exe`.

The activity was associated with:

* **T1016 — System Network Configuration Discovery**
* **T1082 — System Information Discovery**
* **T1087 — Account Discovery**

![Defender Discovery Events](../images/discovery/edr-discovery-events.png)

### 6. Sentinel Investigation

Microsoft Sentinel was used to investigate the process execution events generated during the discovery activity.

The investigation correlated `cmd.exe` with the executed discovery commands and confirmed the associated account and command lines.

![Sentinel Discovery Events](../images/discovery/sentinel-discovery-events.png)

### 7. Result

The discovery phase successfully identified:

* Hostname and operating system information
* Current user and group membership
* Network configuration
* Domain users and groups
* Domain Controller information
* Available network shares

The activity was successfully observed through both **Microsoft Defender for Endpoint** and **Microsoft Sentinel**, providing endpoint and SIEM visibility into the discovery stage of the attack chain.
