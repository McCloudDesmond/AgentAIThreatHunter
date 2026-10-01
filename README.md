# AgentAIThreatHunter

A Python-based Windows threat-hunting tool that monitors Windows Security events and uses an AI investigation layer to help analyze potentially suspicious activity.

## Project Overview

AgentAIThreatHunter was created as a defensive Windows security laboratory project.

The tool continuously monitors the Windows Security Event Log, detects new security events, and displays information such as event IDs, timestamps, computer information, and event data.

When OpenAI API access is available, the collected events can also be sent to an AI investigation layer for additional analysis.

## Features

- Real-time monitoring of Windows Security events
- Detects new security events as they occur
- Monitors authentication and process-related events
- Tracks successful and failed login activity
- Searches events by username, IP address, and hostname
- Supports Windows Event IDs:
  - 4624 — Successful login
  - 4625 — Failed login
  - 4648 — Explicit credential use
  - 4688 — Process creation
- AI-assisted security event investigation
- Read-only access to Windows Security logs
- Defensive analysis designed for an authorized laboratory environment

## Technologies

- Python
- Windows Security Event Log
- pywin32
- OpenAI API
- Windows PowerShell

## How It Works

```text
Windows Security Event Log
            |
            v
    Event Collector
            |
            v
   New Event Detection
            |
            v
     Event Analysis
            |
            +-------------------+
            |                   |
            v                   v
     Local Monitoring     OpenAI Analysis
                              |
                              v
                     AI Investigation Report
