# Windows DFIR Lab 70 — Investigation Timeline

## Timeline Overview

The timeline below documents the major stages of the PresentationHost abuse investigation, from initial host discovery and lab preparation through baseline collection and the planned telemetry analysis.

The timeline distinguishes between **confirmed activities** and investigation stages that require supporting endpoint telemetry before they can be treated as confirmed findings.

## Investigation Timeline

| Time | Event | Evidence / Observation |
|---|---|---|
| `08:30:26` | Host environment identified | Hostname, user, Windows version, and timestamp collected |
| `08:34` | Investigation workspace created | `C:\PresentationHostAbuseLab` and supporting directories created |
| `08:35:11` | Benign payload created | `presentationhost-payload.ps1` created under `Payload` |
| `08:35` | Payload validated | Payload contents reviewed |
| `08:35` | Payload SHA256 calculated | `68626A0D372734CFBDA7B4F3C9007FC1C469BCCDC6ED89FCE7B0B6F1DF03A6FD` |
| `08:35:59` | Filesystem baseline captured | `Evidence\baseline.txt` created |
| After baseline | PresentationHost investigation | Execution and telemetry analysis initiated |
| After execution | Sysmon Event ID 1 analysis | Parent process and command-line investigation |
| After execution | Process-tree reconstruction | PresentationHost parent/child relationships |
| After execution | Sysmon Event ID 11 analysis | Related file creation activity |
| Final stage | Evidence correlation | Process, file, user, and telemetry correlation |
| Final stage | Analyst assessment | Benign or suspicious determination based on evidence |

## 1. Environment Discovery

### `08:30:26` — Host Information Collection

The investigation began by collecting the endpoint identity and environment.

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
```

This information establishes the system and user context for the remainder of the investigation.

## 2. Investigation Workspace Creation

### `08:34` — Lab Directory Preparation

The investigation workspace was created:

```text
C:\PresentationHostAbuseLab
```

Supporting directories were created:

```text
C:\PresentationHostAbuseLab\Evidence
C:\PresentationHostAbuseLab\Output
C:\PresentationHostAbuseLab\Payload
```

These directories separate the investigation evidence, expected output, and controlled payload.

## 3. Payload Creation

### `08:35:11` — Controlled Payload Created

The benign PowerShell investigation payload was created at:

```text
C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1
```

The payload records:

- Execution time
- Hostname
- Current user
- Benign execution status

The payload does not modify or replace the legitimate `PresentationHost.exe` executable.

## 4. Payload Integrity Verification

### `08:35` — SHA256 Hash Recorded

The payload was hashed using SHA256.

Observed value:

```text
68626A0D372734CFBDA7B4F3C9007FC1C469BCCDC6ED89FCE7B0B6F1DF03A6FD
```

This provides an integrity reference for the exact payload used during the investigation.

## 5. Baseline Collection

### `08:35:59` — Filesystem Baseline Captured

A pre-activity filesystem baseline was stored at:

```text
C:\PresentationHostAbuseLab\Evidence\baseline.txt
```

The baseline included:

```text
C:\PresentationHostAbuseLab\Evidence
C:\PresentationHostAbuseLab\Output
C:\PresentationHostAbuseLab\Payload
C:\PresentationHostAbuseLab\Evidence\baseline.txt
C:\PresentationHostAbuseLab\Payload\presentationhost-payload.ps1
```

The payload was recorded as approximately `512` bytes at baseline collection.

## 6. PresentationHost Investigation

### Post-Baseline — Executable Verification

The primary executable under investigation is:

```text
C:\Windows\System32\PresentationHost.exe
```

A possible 32-bit copy may also exist at:

```text
C:\Windows\SysWOW64\PresentationHost.exe
```

The executable path and metadata should be verified before interpreting related process activity.

## 7. Process Creation Analysis

### Post-Execution — Sysmon Event ID 1

The next investigation stage is to identify whether `PresentationHost.exe` generated a Sysmon Event ID 1 process creation event.

Relevant fields include:

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

The primary investigative question is:

> What process caused `PresentationHost.exe` to execute?

## 8. Process Tree Reconstruction

### Post-Execution — Parent and Child Analysis

If PresentationHost process telemetry is identified, the execution chain should be reconstructed:

```text
Parent Process
      |
      +-- PresentationHost.exe
                |
                +-- Child Process
                |
                +-- Child Process
```

The actual parent and child processes must be established from telemetry rather than assumed from the investigation design.

## 9. Child Process Review

### Post-Execution — Suspicious Child Process Analysis

Any child process spawned by PresentationHost.exe should be examined.

Particular attention should be given to:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
rundll32.exe
mshta.exe
```

The presence of one of these processes is not sufficient to establish malicious activity. Command-line arguments, parent process, user, timestamp, and resulting activity should be correlated.

## 10. File Activity Analysis

### Post-Execution — Sysmon Event ID 11

Sysmon Event ID 11 should be reviewed for files created during the investigation.

The expected benign output is:

```text
C:\PresentationHostAbuseLab\Output\presentationhost-result.txt
```

Additional files created outside the expected lab directory should be investigated for their relationship to the PresentationHost process.

## 11. Wazuh Correlation

### Post-Execution — SIEM Validation

Wazuh should be reviewed to determine whether the relevant process and file telemetry was successfully forwarded from the endpoint.

Important process fields include:

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

Wazuh results should be correlated with the underlying Sysmon events.

## 12. Final Evidence Correlation

The final timeline should connect:

```text
Host Activity
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
Child Process
      |
      v
File Activity
      |
      v
Wazuh / Sysmon Telemetry
      |
      v
Analyst Assessment
```

The objective is to establish whether the complete execution chain is consistent with legitimate behavior or contains suspicious indicators.

## Current Timeline Status

The following timeline events are currently confirmed:

- Host environment collection
- Investigation workspace creation
- Benign payload creation
- Payload hash generation
- Filesystem baseline collection

The following events require supporting telemetry before they can be recorded as confirmed findings:

- PresentationHost.exe execution
- PresentationHost parent process
- PresentationHost command line
- PresentationHost child processes
- Associated file creation activity
- Related network activity

## Final Timeline Assessment

The timeline currently establishes the preparation and baseline phases of the investigation.

A final behavioral assessment should only be added after the relevant Sysmon and Wazuh telemetry has been captured and correlated. This ensures that the timeline reflects actual endpoint evidence rather than assumptions based on the intended laboratory procedure.
