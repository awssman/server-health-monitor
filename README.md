# Server Health Monitor

Python script that monitors server health metrics and generates automated reports.

Built as a portfolio project to demonstrate Python automation and system monitoring skills.

## What It Monitors

| Metric | Thresholds | Levels |
|--------|-----------|--------|
| CPU Usage | 70% warning, 90% critical | OK / WARNING / CRITICAL |
| Memory Usage | 75% warning, 90% critical | OK / WARNING / CRITICAL |
| Disk Usage | 80% warning, 95% critical | OK / WARNING / CRITICAL |
| System Load | 4.0 warning, 8.0 critical | OK / WARNING / CRITICAL |
| Services | active / inactive | nginx, docker, fail2ban, ssh |

## Usage

    python3 server_health_monitor.py

## Sample Output

    ============================================================
      SERVER HEALTH REPORT
    ============================================================

      Hostname:  server-01
      OS:        Linux 6.1.0
      Uptime:    47d 12h 30m
      Status:    OK

      METRICS

      CPU       ######........................    23.0%
      Memory    ##################............    61.2%
      Disk      #########################.....    82.4%
      Load      ..............................     0.4avg

      SERVICES

      nginx                active
      docker               active
      fail2ban             active
      ssh                  active

    ============================================================

## Features

- OOP architecture with dataclasses and Enum
- 4-level alert system (OK, WARNING, CRITICAL, EMERGENCY)
- Visual progress bars in terminal output
- Color-coded output for quick assessment
- JSON report generation with timestamps
- Service status checking via systemctl
- Reads directly from /proc for accuracy
- No external dependencies — stdlib only

## Architecture

    SystemCollector     hostname, IP, OS, uptime
    MetricCollector     CPU, memory, disk, load
    ServiceChecker      systemctl service status
    HealthReport        aggregates all data
    ReportGenerator     terminal output + JSON export

## Requirements

- Python 3.10+
- Linux (reads from /proc and uses systemctl)
- No external dependencies

## Author

Awssman — IT Systems Administrator
