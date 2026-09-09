# Windows DFIR Lab 70 — Troubleshooting Notes

## Troubleshooting Overview

This section documents common issues that may occur while investigating `PresentationHost.exe` activity using Sysmon and Wazuh. The troubleshooting process focuses on validating the endpoint, executable path, payload, telemetry, and filesystem artifacts before drawing investigative conclusions.

The most important principle is to distinguish between **missing telemetry** and **absence of activity**. An event that is not visible in the SIEM should not automatically be interpreted as evidence that the activity did not occur.

## 1. PresentationHost.exe Not Found

### Issue

The expected executable cannot be found at:

```text
C:\Windows\System32\PresentationHost.exe
```

### Validation

```powershell
Test-Path "C:\Windows\System32\PresentationHost.exe"
Test-Path "C:\Windows\SysWOW64\PresentationHost.exe"
```

### Troubleshooting

Check both locations before concluding that PresentationHost.exe is unavailable.

```powershell
Get-ChildItem "C:\Windows\System32\PresentationHost.exe" -ErrorAction SilentlyContinue
Get-ChildItem "C:\Windows\SysWOW64\PresentationHost.exe" -ErrorAction SilentlyContinue
```

If neither path exists, the investigation should not assume that PresentationHost.exe executed.

## 2. PresentationHost.exe Path Appears Suspicious

### Issue

Telemetry shows `PresentationHost.exe`, but the executable path is different from the expected Windows location.

### Investigation

Verify the reported path and compare it with:

```text
C:\Windows\System32\PresentationHost.exe
C:\Windows\SysWOW64\PresentationHost.exe
```

An executable with the same filename running from a user-writable or temporary directory should receive additional scrutiny.

### Analyst Note

The filename alone is not sufficient for establishing legitimacy. The full path, file metadata, hash, parent process, and execution context should be considered together.

## 3. Sysmon Event ID 1 Not Visible

### Issue

No PresentationHost-related process creation event is visible in the expected telemetry.

### Validation

Check whether the Sysmon service is running:

```powershell
Get-Service Sysmon*
```

Review recent process creation events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 20 |
Select-Object TimeCreated, Message
```

### Possible Causes

- PresentationHost.exe was not executed.
- The activity occurred outside the search timeframe.
- Sysmon is not running.
- Sysmon configuration is filtering the event.
- The event exists locally but has not reached Wazuh.
- The search did not match the exact process name or message format.

### Analyst Note

A missing Event ID 1 record should be treated as a **telemetry limitation until validated**, not as proof that no execution occurred.

## 4. Sysmon Event ID 11 Not Visible

### Issue

Expected file creation activity is not visible in Sysmon Event ID 11.

### Validation

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 11
} -MaxEvents 20 |
Select-Object TimeCreated, Message
```

Also inspect the expected output directory directly:

```powershell
Get-ChildItem "C:\PresentationHostAbuseLab\Output" -Force
```

### Possible Causes

- The expected file was never created.
- The file was created before the search window.
- Sysmon Event ID 11 is not being collected.
- The Sysmon configuration excludes the relevant path or event.
- Wazuh has not received the event.

## 5. Payload Not Found

### Issue

The controlled payload cannot be located.

Expected path:

```text
C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1
```

### Validation

```powershell
Test-Path "C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1"

Get-Item "C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1" -ErrorAction SilentlyContinue
```

If the file exists, validate its contents:

```powershell
Get-Content "C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1"
```

## 6. Payload Hash Does Not Match

### Issue

The calculated SHA256 differs from the recorded investigation hash.

Expected value:

```text
68626A0D372734CFBDA7B4F3C9007FC1C469BCCDC6ED89FCE7B0B6F1DF03A6FD
```

### Validation

```powershell
Get-FileHash "C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1" -Algorithm SHA256
```

### Troubleshooting

If the hash differs:

- Verify that the correct payload file is being examined.
- Check whether the file was modified after creation.
- Compare the file content with the original payload.
- Do not replace the recorded hash simply to make the evidence match.

A changed hash should be documented as an evidence difference.

## 7. Baseline File Missing

### Issue

The filesystem baseline cannot be located.

Expected path:

```text
C:\PresentationHostAbuseLab\Evidence\baseline.txt
```

### Validation

```powershell
Test-Path "C:\PresentationHostAbuseLab\Evidence\baseline.txt"
```

List the evidence directory:

```powershell
Get-ChildItem "C:\PresentationHostAbuseLab\Evidence" -Force
```

### Analyst Note

The baseline is important because it provides the known pre-activity state of the lab directory. Without it, post-activity file changes may be more difficult to distinguish from existing artifacts.

## 8. Output File Not Created

### Issue

The expected output file is not present:

```text
C:\PresentationHostAbuseLab\Output\presentationhost-result.txt
```

### Validation

```powershell
Test-Path "C:\PresentationHostAbuseLab\Output\presentationhost-result.txt"
```

If present:

```powershell
Get-Item "C:\PresentationHostAbuseLab\Output\presentationhost-result.txt"
Get-Content "C:\PresentationHostAbuseLab\Output\presentationhost-result.txt"
```

### Possible Causes

- The benign payload did not execute.
- The output path was incorrect.
- The payload was modified.
- The activity occurred under a different execution context.
- File creation telemetry was not captured.

The absence of the output file should therefore be investigated rather than automatically interpreted as a failed telemetry collection.

## 9. Wazuh Does Not Show the Event

### Issue

Sysmon events are present locally, but the corresponding event cannot be located in Wazuh.

### Validation

First confirm the event exists locally:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 10 |
Select-Object TimeCreated, Message
```

Then verify Wazuh agent status:

```powershell
Get-Service WazuhSvc
```

### Possible Causes

- Wazuh agent is not running.
- Sysmon logs are not being collected by the agent.
- The event has not yet been indexed.
- The SIEM search timeframe is incorrect.
- The Wazuh decoder or rule does not expose the expected fields.

### Analyst Note

When possible, use the local Sysmon event as the primary source of truth and use Wazuh to validate SIEM visibility.

## 10. Parent Process Is Missing

### Issue

A PresentationHost process event is available, but the parent process information is missing or incomplete.

### Investigation

Review the complete Event ID 1 record rather than only the process name.

Important fields include:

```text
ParentImage
ParentCommandLine
ParentProcessId
ParentProcessGuid
ProcessGuid
User
UtcTime
```

### Analyst Note

Without parent-process information, the execution chain may be incomplete. The limitation should be documented rather than filled with assumptions.

## 11. Child Process Not Observed

### Issue

PresentationHost.exe is visible, but no child process is identified.

### Investigation

Search Event ID 1 around the PresentationHost execution timestamp and correlate process IDs and timestamps.

Potential child processes of interest include:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
rundll32.exe
mshta.exe
```

### Analyst Note

The absence of a visible child process does not automatically mean that no child process existed. Event collection, process lifetime, and telemetry timing should be considered.

## 12. Timeline Does Not Match

### Issue

The timestamps from the payload, filesystem artifacts, and Sysmon events do not align.

### Troubleshooting

Compare:

- Local system time
- Sysmon `UtcTime`
- PowerShell execution time
- File creation time
- Wazuh ingestion time

When documenting the investigation, distinguish between **event time** and **SIEM ingestion time**.

## 13. Avoiding Unsupported Conclusions

### Issue

Expected telemetry is missing, but the investigation design suggests that an execution should have occurred.

### Correct Approach

Do not document the expected behavior as a confirmed observation.

For example, do not state:

```text
PresentationHost.exe spawned cmd.exe.
```

unless corresponding telemetry confirms the relationship.

Instead document:

```text
PresentationHost.exe execution was part of the intended investigation workflow, but a corresponding confirmed process-chain event was not available in the collected evidence.
```

This preserves the integrity of the DFIR analysis.

## Evidence-Based Troubleshooting Principle

The investigation should follow this sequence:

```text
Validate Activity
        |
        v
Validate Telemetry
        |
        v
Validate Timestamp
        |
        v
Validate Process Relationship
        |
        v
Validate File Activity
        |
        v
Correlate Evidence
        |
        v
Make Assessment
```

The absence of a telemetry record should never be used as a substitute for evidence.

## Final Troubleshooting Assessment

The laboratory environment, controlled payload, payload hash, and filesystem baseline were successfully established.

The main troubleshooting requirement is to validate whether PresentationHost-related process and file telemetry was actually captured. Until the relevant Sysmon and Wazuh evidence is available, the execution chain should remain classified as **unconfirmed** rather than being reconstructed from assumptions.

This approach ensures that the investigation remains reproducible, evidence-based, and suitable for SOC/DFIR documentation.
