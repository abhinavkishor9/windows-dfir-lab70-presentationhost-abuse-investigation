# Investigation Timeline

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

