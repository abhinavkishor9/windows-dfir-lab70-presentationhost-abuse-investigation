# Investigation Notes

## Investigation Environment

- Operating System: Windows 10 Pro
- Hostname: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- Windows Version: `2009`
- Investigation Date: 09 September 2026
- Initial Timestamp: `09 September 2026 08:30:26`
- Sysmon: Enabled
- Wazuh Agent: Enabled
- Primary Telemetry: Sysmon Event ID 1
- File Activity Telemetry: Sysmon Event ID 11
- Investigation Directory: `C:\PresentationHostAbuseLab`

## Investigation Directory

The investigation workspace was created at:

```text
C:\PresentationHostAbuseLab\
├── Evidence\
├── Output\
└── Payload\
```

The directory structure separates evidence collection, expected output, and the controlled payload.

## Host Baseline

The initial host information was collected using PowerShell:

```powershell
hostname
whoami
Get-Date
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
```

Observed values:

```text
Hostname:
DESKTOP-9MMM37V

User:
desktop-9mmm37v\dell

Operating System:
Windows 10 Pro

Windows Version:
2009

Timestamp:
09 September 2026 08:30:26
```

This information establishes the endpoint and user context before further investigation activity.

## PresentationHost.exe Verification

The primary executable under investigation is:

```text
C:\Windows\System32\PresentationHost.exe
```

A possible 32-bit copy may also be present at:

```text
C:\Windows\SysWOW64\PresentationHost.exe
```

The executable should be examined for:

- Full path
- File size
- Creation time
- Last write time
- SHA256 hash

The purpose of this step is to determine whether the executable involved in telemetry is located in an expected Windows directory.

A legitimate executable path alone does not establish that the surrounding activity is benign.

## Controlled Payload

A benign PowerShell payload was created at:

```text
C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1
```

The payload records:

- Execution timestamp
- Hostname
- Current user
- Benign execution status

The expected output artifact is:

```text
C:\PresentationHostAbuseLab\Output\presentationhost-result.txt
```

The payload was specifically designed for controlled investigation activity and does not modify, replace, or tamper with `PresentationHost.exe`.

## Payload Hash

The SHA256 hash recorded for the payload was:

```text
68626A0D372734CFBDA7B4F3C9007FC1C469BCCDC6ED89FCE7B0B6F1DF03A6FD
```

This hash provides an integrity reference for the payload used during the investigation.

## Baseline Evidence

A filesystem baseline was captured before subsequent investigation activity:

```text
C:\PresentationHostAbuseLab\Evidence\baseline.txt
```

The baseline recorded the following artifacts:

```text
C:\PresentationHostAbuseLab\Evidence
C:\PresentationHostAbuseLab\Output
C:\PresentationHostAbuseLab\Payload
C:\PresentationHostAbuseLab\Evidence\baseline.txt
C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1
```

The payload file was approximately `512` bytes at the time of baseline collection.

This baseline provides a reference for identifying newly created artifacts during later activity.

## Process Investigation

### Sysmon Event ID 1

Sysmon Event ID 1 is the primary telemetry source for reconstructing the process execution chain.

The following fields are particularly important:

```text
Image
CommandLine
ParentImage
ParentCommandLine
ProcessId
ParentProcessId
ProcessGuid
ParentProcessGuid
User
UtcTime
```

The investigation should use these fields to establish:

```text
Who launched the process?
What launched it?
What command line was used?
When did it execute?
What process did it launch?
```

## Parent Process Analysis

The parent process is one of the most important indicators when investigating a trusted Windows binary.

The expected investigative relationship is:

```text
Parent Process
      |
      +-- PresentationHost.exe
```

The actual parent process must be established from endpoint telemetry.

An unexpected parent process may increase the likelihood that the execution requires further investigation.

Examples include unusual scripting engines, office applications, archive utilities, temporary executables, or processes executing from user-writable directories.

## Command-Line Analysis

The PresentationHost command line should be reviewed in full rather than relying only on the executable name.

Important questions include:

- Were unusual arguments supplied?
- Was the process started from an unusual working directory?
- Was an external file referenced?
- Was a suspicious application or script involved?
- Does the command line correspond to expected WPF/XBAP behavior?

Command-line analysis is especially useful when a trusted executable is suspected of being used as an execution mechanism.

## Child Process Investigation

The investigation should identify any processes created by `PresentationHost.exe`.

Potentially interesting child processes include:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
rundll32.exe
mshta.exe
```

The presence of one of these processes alone does not establish malicious activity.

The analyst should correlate:

```text
Parent Process
+
Child Process
+
Command Line
+
User
+
Timestamp
+
File Activity
```

A suspicious child process combined with an unusual command line or unexpected file activity would increase investigation priority.

## File Activity Investigation

Sysmon Event ID 11 should be used to identify files created during the activity.

The expected benign output artifact is:

```text
C:\PresentationHostAbuseLab\Output\presentationhost-result.txt
```

The analyst should determine whether additional files were created in:

```text
C:\PresentationHostAbuseLab
```

or other locations such as:

```text
C:\Users\<user>\AppData\
C:\Users\<user>\Downloads\
C:\Windows\Temp\
C:\ProgramData\
```

Unexpected scripts, executables, DLLs, or temporary files should be correlated with the process execution timeline.

## Output Validation

The expected output file can be checked using:

```powershell
Get-Item "C:\PresentationHostAbuseLab\Output\presentationhost-result.txt"
Get-Content "C:\PresentationHostAbuseLab\Output\presentationhost-result.txt"
```

The contents should correspond to the benign payload's expected execution output.

## Wazuh Validation

Wazuh is used to validate whether endpoint process telemetry is visible through the SIEM.

Relevant process metadata may include:

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

Wazuh visibility should be compared with the underlying Sysmon telemetry to determine whether sufficient process context is available for investigation.


## Evidence Assessment

### Confirmed

The investigation confirms:

- Endpoint identity
- User context
- Windows operating system
- Investigation directory creation
- Controlled payload creation
- Payload SHA256
- Pre-activity filesystem baseline

### Not Yet Confirmed

The following require corresponding endpoint telemetry before they can be treated as confirmed observations:

- PresentationHost.exe execution
- PresentationHost parent process
- PresentationHost command line
- PresentationHost child processes
- Associated Sysmon Event ID 11 activity
- Related network activity

These items should not be inferred from the laboratory design alone.

