# 02 — RDP Brute Force Attack

## Credential Attack

After the reconnaissance phase identified RDP (`3389/tcp`) on `192.168.10.132`, a controlled RDP brute-force attack was performed against the domain user `MYLAB\Jsmith`.

### 1. RDP Discovery & Brute Force

From Kali, RDP was confirmed as open and Hydra was used to perform the credential attack against the target.

![RDP Brute Force from Kali](../images/rdp-brute-force/attacker-rdp-scan-brute.png)

The attack generated multiple authentication attempts against `192.168.10.132`.

### 2. Defender for Endpoint

Microsoft Defender recorded the RDP activity and multiple failed authentication attempts from `192.168.10.133`, followed by a successful authentication for `MYLAB\Jsmith`.

![Defender RDP Brute Force](../images/rdp-brute-force/edr-brute-force-victim.png)

The activity was associated with **T1021.001 — Remote Desktop Protocol**.

### 3. Sentinel Investigation

Sentinel was used to correlate the authentication events. The results showed multiple **4625 Failed Logon** events followed by a **4624 Successful Logon** from `192.168.10.133`.

![Sentinel Brute Force](../images/rdp-brute-force/sentinel-brute-force-victim.png)

### 4. Manual RDP Login

After obtaining the credentials, a manual RDP connection was performed using `MYLAB\Jsmith`.

Defender identified:

> `MYLAB\Jsmith connected to the device through a Remote Desktop session from 192.168.10.133`

![Successful RDP Access — Defender](../images/rdp-brute-force/edr-rdp-access-victim.png)

The event was mapped to:

* **T1078 — Valid Accounts**
* **T1021.001 — Remote Desktop Protocol**

### 5. Sentinel — Successful RDP

Sentinel confirmed the successful interactive RDP session with:

* `Event ID: 4624`
* `Logon Type: 10 — RemoteInteractive`
* `Account: MYLAB\Jsmith`
* `Source IP: 192.168.10.133`

![Successful RDP Access — Sentinel](../images/rdp-brute-force/sentinel-rdp-access-victim.png)


