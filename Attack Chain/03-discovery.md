# 03 — Discovery

## System & Domain Discovery

After gaining RDP access to the Windows endpoint using the compromised domain account `MYLAB\Jsmith`, discovery activity was performed from the victim machine under the `Jsmith` user context.

### System & Identity Discovery

The following commands were executed:

```cmd
hostname
systeminfo
whoami
whoami /groups
ipconfig /all
```

This provided information about the hostname, operating system, current user, group membership, and network configuration.

![System Identity Discovery](../images/discovery/attacker-system-identity-discovery.png)

![System Information Discovery](../images/discovery/attacker-system-information-discovery.png)

### Domain & Account Discovery

Domain users and groups were enumerated using:

```cmd
net user /domain
net group /domain
```

The output revealed domain accounts and available domain groups.

![Domain Account Discovery](../images/discovery/attacker-domain-account-discovery.png)

### Domain Controller Discovery

The Domain Controller was identified using:

```cmd
nltest /dsgetdc:MYLAB
```

The command identified `DC-01` at `192.168.10.130` as the Domain Controller for the `MYLAB` domain.

![Domain Controller Discovery](../images/discovery/attacker-domain-controller-discovery.png)

### Network Share Discovery

Available network shares on the Domain Controller were enumerated using:

```cmd
net view \\DC-01
```

The results identified the `NETLOGON` and `SYSVOL` shares.

![Network Share Discovery](../images/discovery/attacker-network-share-discovery.png)

### Microsoft Defender for Endpoint

Microsoft Defender for Endpoint recorded the discovery activity performed by `MYLAB\Jsmith`, including execution of `systeminfo.exe`, `ipconfig.exe`, `ARP.EXE`, `net.exe`, and `nltest.exe`.

![Defender Discovery Events](../images/discovery/edr-discovery-events.png)

### Microsoft Sentinel

Microsoft Sentinel was used to investigate the process execution events generated during the discovery activity.

The results confirmed that the discovery commands were executed by `MYLAB\Jsmith` through `cmd.exe`, following the successful RDP compromise.

![Sentinel Discovery Events](../images/discovery/sentinel-discovery-events.png)

### MITRE ATT&CK

* **T1016 — System Network Configuration Discovery**
* **T1082 — System Information Discovery**
* **T1033 — System Owner/User Discovery**
* **T1069.002 — Permission Groups Discovery: Domain Groups**
* **T1018 — Remote System Discovery**
* **T1087.002 — Account Discovery: Domain Account**
* **T1135 — Network Share Discovery**

### Detection Summary

The Discovery phase was successfully observed and validated across **Microsoft Defender for Endpoint and Microsoft Sentinel**. Following the successful RDP compromise, `MYLAB\Jsmith` performed system, identity, domain, Domain Controller, and network share discovery from the compromised Windows endpoint. Defender recorded the associated process executions, while Sentinel provided supporting event data confirming that the discovery commands were executed through `cmd.exe` under the compromised user context.
