# windows-dfir-lab70-presentationhost-abuse-investigation
## Overview

PresentationHost.exe is a legitimate Windows executable associated with Windows Presentation Foundation (WPF) XBAP applications. Because it is a trusted Microsoft binary capable of launching application content, abuse of its execution chain can be useful for demonstrating LOLBIN-style behavior.

From a SOC perspective, the important point is not simply that PresentationHost.exe executed. The investigation should determine:

- Why was PresentationHost.exe launched?
- What application or file caused it to execute?
- What was its parent process?
- What command line and arguments were used?
- Did it create child processes?
- Did it access suspicious files or directories?
- Did the execution result in network activity?
- Does the activity match normal WPF/XBAP behavior or an abnormal execution chain?

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

A Windows workstation is being investigated for activity involving PresentationHost.exe, a legitimate Microsoft executable associated with Windows Presentation Foundation (WPF) applications. Since trusted Windows binaries can also be used as part of suspicious execution chains, the SOC analyst must examine the surrounding behavior before deciding whether the activity is legitimate or potentially malicious.

The investigation focuses on:

- Verifying the legitimate PresentationHost.exe executable and its path.
- Identifying the parent process and command-line arguments.
- Examining any child processes spawned during execution.
- Correlating related file activity with Sysmon and Wazuh telemetry.
- Determining whether the overall execution chain is consistent with normal behavior or potential abuse.

## Investigation Objectives

- Understand the legitimate purpose and security relevance of PresentationHost.exe.
- Verify the expected location and metadata of the legitimate executable.
- Establish a clean baseline for the investigation environment.
- Create and hash a controlled benign payload for the investigation.
- Analyze Sysmon Event ID 1 for PresentationHost process creation.
- Identify the parent process and examine command-line arguments.
- Investigate any child processes spawned by PresentationHost.exe.
- Analyze Sysmon Event ID 11 for related file creation activity.
- Correlate process, file, user, and SIEM telemetry to reconstruct the execution chain.
- Distinguish legitimate PresentationHost activity from indicators of potential abuse.

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

