# Windows DFIR Lab 70 — PresentationHost Abuse Investigation

## Overview

This lab investigates the use of the legitimate Windows executable `PresentationHost.exe`, associated with Windows Presentation Foundation (WPF) and XBAP application functionality. Although `PresentationHost.exe` is a legitimate Microsoft binary, its execution context can still be relevant during a security investigation.

The investigation uses a controlled and benign environment to examine how `PresentationHost.exe` activity should be analyzed through executable verification, process creation telemetry, parent-child relationships, command-line arguments, child processes, and file activity.

The objective is not to classify `PresentationHost.exe` as malicious by default, but to determine whether its execution context and surrounding activity are consistent with legitimate application behavior or a potentially suspicious execution pattern.

## Lab Environment

- Operating System: Windows 10 Pro
- Hostname: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- Windows Version: `2009`
- Sysmon: Enabled
- Wazuh Agent: Enabled
- Primary Telemetry: Sysmon Event ID 1
- File Activity Telemetry: Sysmon Event ID 11
- Investigation Directory: `C:\PresentationHostAbuseLab`

## Investigation Scenario

A Windows workstation is being examined for activity involving the legitimate Windows executable `PresentationHost.exe`.

The analyst needs to determine:

- Whether `PresentationHost.exe` is executing from the expected Windows directory.
- What process caused `PresentationHost.exe` to execute.
- What command-line arguments were supplied.
- Whether `PresentationHost.exe` created any child processes.
- Whether suspicious interpreters or LOLBINs were launched.
- What files were created during the activity.
- Whether the resulting activity is consistent with normal application behavior.
- Whether the relevant telemetry is visible through Sysmon and Wazuh.
- Whether the evidence supports a benign or suspicious assessment.

## Investigation Objectives

1. Understand the purpose and security relevance of `PresentationHost.exe`.
2. Establish a clean baseline for the investigation host and lab directory.
3. Verify the legitimate `PresentationHost.exe` executable path.
4. Create and hash a controlled benign investigation payload.
5. Capture `PresentationHost.exe` process creation telemetry using Sysmon Event ID 1.
6. Identify the parent process and reconstruct the process lineage.
7. Examine command-line arguments and execution context.
8. Identify and investigate unexpected child processes.
9. Correlate process execution with resulting file activity.
10. Validate the availability of relevant telemetry through Wazuh.
11. Distinguish confirmed observations from telemetry limitations and assumptions.

## Investigation Workflow

```text
Environment Baseline
        |
        v
Verify PresentationHost.exe
        |
        v
Controlled Investigation Activity
        |
        v
PresentationHost.exe
        |
        v
Parent Process
        |
        v
Command Line
        |
        v
Child Process Activity
        |
        v
File Activity
        |
        v
Sysmon / Wazuh Telemetry
        |
        v
Process + File Correlation
        |
        v
Analyst Assessment
```

## Key Evidence

### Host Information

The initial environment discovery produced the following information:

- Hostname: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- Operating System: Windows 10 Pro
- Windows Version: `2009`
- Initial timestamp: `09 September 2026 08:30:26`

### Investigation Directory

The investigation workspace was created at:

`C:\PresentationHostAbuseLab`

The following directories were created:

```text
C:\PresentationHostAbuseLab\
├── Evidence\
├── Output\
└── Payload\
```

### Controlled Payload

A benign PowerShell payload was created at:

`C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1`

The payload records:

- Execution time
- Hostname
- Current user
- Benign execution status

The expected output file is:

`C:\PresentationHostAbuseLab\Output\presentationhost-result.txt`

The payload does not modify, replace, or tamper with the legitimate `PresentationHost.exe` executable.

### Payload Integrity

The SHA256 hash recorded for the payload was:

```text
68626A0D372734CFBDA7B4F3C9007FC1C469BCCDC6ED89FCE7B0B6F1DF03A6FD
```

This hash provides an integrity reference for the exact payload used during the investigation.

### Baseline Evidence

A pre-activity filesystem baseline was captured at:

`C:\PresentationHostAbuseLab\Evidence\baseline.txt`

The baseline contained the initial investigation directory structure, including:

```text
C:\PresentationHostAbuseLab\Evidence
C:\PresentationHostAbuseLab\Output
C:\PresentationHostAbuseLab\Payload
C:\PresentationHostAbuseLab\Evidence\baseline.txt
C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1
```

The payload was recorded as approximately `512` bytes during baseline collection.

## PresentationHost.exe Verification

The primary executable under investigation is:

`C:\Windows\System32\PresentationHost.exe`

A possible 32-bit copy may also exist at:

`C:\Windows\SysWOW64\PresentationHost.exe`

The executable should be verified for:

- Full path
- File size
- Creation time
- Last write time
- SHA256 hash

This establishes whether the executable involved in the investigation is located in the expected Windows directory.

## Process Investigation

### Sysmon Event ID 1

Sysmon Event ID 1 provides process creation telemetry that can be used to reconstruct the `PresentationHost.exe` execution chain.

Important fields include:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `ProcessId`
- `ParentProcessId`
- `ProcessGuid`
- `ParentProcessGuid`
- `User`
- `UtcTime`

The primary investigative question is:

> What process caused `PresentationHost.exe` to execute?

The parent process and command line should be analyzed together to determine the execution context.

### Process Tree

The investigation should reconstruct the observed process lineage:

```text
Parent Process
      |
      +-- PresentationHost.exe
                |
                +-- Child Process
                |
                +-- Child Process
```

The actual parent and child processes must be established from endpoint telemetry rather than assumed from the expected lab design.

### Child Process Review

Particular attention should be given to unexpected processes such as:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
rundll32.exe
mshta.exe
```

The presence of these processes does not automatically indicate malicious activity. Their command lines, parent processes, user context, timestamps, and associated files must be analyzed together.

## File Activity Investigation

### Sysmon Event ID 11

Sysmon Event ID 11 should be reviewed for files created during the investigation.

The expected benign output is:

`C:\PresentationHostAbuseLab\Output\presentationhost-result.txt`

The analyst should also investigate:

- Unexpected scripts
- Executables
- DLLs
- Temporary files
- Files created in user-writable directories
- Files created outside the expected lab directory

The resulting file can be validated with:

```powershell
Get-Item "C:\PresentationHostAbuseLab\Output\presentationhost-result.txt"
Get-Content "C:\PresentationHostAbuseLab\Output\presentationhost-result.txt"
```

## Telemetry

### Sysmon

The primary telemetry used in the investigation is Sysmon.

**Event ID 1 — Process Create**

Important fields include:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `ProcessId`
- `ParentProcessId`
- `ProcessGuid`
- `ParentProcessGuid`
- `User`
- `UtcTime`

**Event ID 11 — File Create**

This event is used to identify files created during the activity and correlate those artifacts with the process execution timeline.

### Wazuh

Wazuh is used to validate SIEM visibility of the endpoint activity and provide additional process metadata where available.

Relevant fields include:

```text
data.win.eventdata.image
data.win.eventdata.parentImage
data.win.eventdata.parentCommandLine
data.win.eventdata.parentProcessId
data.win.eventdata.parentProcessGuid
data.win.eventdata.commandLine
data.win.eventdata.currentDirectory
data.win.eventdata.user
data.win.eventdata.integrityLevel
data.win.eventdata.hashes
```

## Evidence Collection

Evidence is stored under:

`C:\PresentationHostAbuseLab\Evidence`

The investigation evidence currently includes:

```text
baseline.txt
```

The controlled payload is stored under:

`C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1`

The payload SHA256 is:

```text
68626A0D372734CFBDA7B4F3C9007FC1C469BCCDC6ED89FCE7B0B6F1DF03A6FD
```

## Investigation Findings

### Confirmed Findings

The following observations were confirmed during the laboratory setup:

- Hostname: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- Operating System: Windows 10 Pro
- Windows Version: `2009`
- Investigation directory successfully created
- Payload successfully created
- Payload SHA256 successfully recorded
- Pre-activity filesystem baseline successfully captured

### Current Telemetry Status

The available evidence confirms the environment preparation, controlled payload, payload integrity, and baseline collection.

A confirmed `PresentationHost.exe` process creation event, parent process, child process chain, or related Sysmon Event ID 11 activity has not been established from the evidence currently collected.

Therefore, the investigation does not claim that a malicious `PresentationHost.exe` execution occurred.

## Important Evidence Interpretation

The presence of `PresentationHost.exe` alone is not sufficient to classify the activity as malicious.

The stronger investigative signal comes from the complete execution context:

- Executable path
- Parent process
- Command line
- User context
- Child processes
- File activity
- Network activity
- Temporal correlation

A legitimate Windows binary may participate in suspicious behavior, but the binary itself should not be treated as evidence of compromise without supporting telemetry.

## SOC Detection Takeaway

A detection for `PresentationHost.exe` should not rely solely on the process name.

Useful investigative signals include:

- Execution from an unusual directory
- Unusual parent process
- Suspicious command-line arguments
- Execution from a user-writable location
- `cmd.exe`, PowerShell, or scripting-engine child processes
- Unexpected file creation
- Related network activity
- Execution under an unexpected user or integrity level
- Correlation with persistence or other suspicious activity

The broader lesson is to investigate the **execution chain and resulting behavior**, rather than treating a legitimate Windows binary as malicious simply because it appears in telemetry.

## Final Assessment

**Classification: Controlled Investigation / Pending Execution Telemetry**

The laboratory environment and benign payload were successfully prepared, and a filesystem baseline was established.

The current evidence does not demonstrate a confirmed malicious `PresentationHost.exe` execution chain. A final assessment requires the relevant process creation, parent-child relationship, command-line, and file activity telemetry to be captured and correlated.

The investigation therefore remains evidence-driven: **verify the binary, reconstruct the execution chain, correlate the activity, and only then determine whether the behavior is benign or suspicious.**
