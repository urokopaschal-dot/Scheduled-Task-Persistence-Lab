# Scheduled Task Persistence Lab (MITRE ATT&CK T1053.005)

## Objective
Learn how attackers establish persistence by creating a scheduled task that automatically executes a program whenever a user logs on.

## MITRE ATT&CK
- Tactic: Persistence
- Technique: T1053.005 - Scheduled Task

## Lab Environment
- Windows 10
- Sysmon
- Splunk

## Attack Simulation

Command:

```cmd
schtasks /create /sc onlogon /tn EvilTask /tr "notepad.exe"
```

## What the Command Does
- Creates a scheduled task named EvilTask.
- Configures the task to run whenever a user logs on.
- Launches Notepad automatically after login.

## Verification

List scheduled tasks:

```cmd
schtasks /query /tn EvilTask /v
```

## Detection

Example Splunk query:

```spl
index=* (EventCode=1 OR EventCode=4698)
```

Hunt specifically for the task:

```spl
index=* "EvilTask"
```

## Investigation Questions
- Which process created the scheduled task?
- Which user account created it?
- What executable is configured to run?
- Does the task name appear legitimate?
- Was the task created recently?

## Indicators of Suspicious Activity
- Tasks created by cmd.exe or powershell.exe
- Tasks running from AppData or Temp folders
- Random or misleading task names
- Tasks configured to run at logon or startup

## Defensive Recommendations
- Monitor Event ID 4698 for task creation.
- Enable Sysmon process creation logging.
- Investigate newly created scheduled tasks.
- Alert on tasks launching unusual executables.

## Skills Demonstrated
- Windows Persistence
- Scheduled Task Analysis
- Splunk Threat Hunting
- MITRE ATT&CK Mapping
- SOC Investigation
