#!/usr/bin/env python3
"""
Server Health Monitor — أداة مراقبة صحة الخادم
==============================================
سكربت Python لمراقبة أداء الخوادم وتوليد تقارير PDF تلقائية.
يقوم بفحص استخدام المعالج، الذاكرة، القرص، والشبكة
مع إرسال تنبيهات عند تجاوز الحدود المحددة.

المطور: Awssman Abu Al Ahbas
التاريخ: 2025
"""

import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

class AlertLevel(Enum):
    OK = "OK"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    EMERGENCY = "EMERGENCY"

THRESHOLDS = {
    "cpu_warning": 70,
    "cpu_critical": 90,
    "memory_warning": 75,
    "memory_critical": 90,
    "disk_warning": 80,
    "disk_critical": 95,
    "load_warning": 4.0,
    "load_critical": 8.0,
}

MONITORED_SERVICES = [
    "nginx",
    "docker",
    "fail2ban",
    "ssh",
]


# ──────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────

@dataclass
class MetricResult:
    name: str
    value: float
    unit: str
    level: AlertLevel
    message: str
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "level": self.level.value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ServiceStatus:
    name: str
    is_active: bool
    uptime: Optional[str] = None
    pid: Optional[int] = None


@dataclass
class HealthReport:
    hostname: str
    ip_address: str
    os_info: str
    kernel: str
    uptime: str
    timestamp: datetime
    metrics: list[MetricResult]
    services: list[ServiceStatus]
    overall_level: AlertLevel = AlertLevel.OK

    def calculate_overall(self):
        levels = [m.level for m in self.metrics]
        if AlertLevel.EMERGENCY in levels:
            self.overall_level = AlertLevel.EMERGENCY
        elif AlertLevel.CRITICAL in levels:
            self.overall_level = AlertLevel.CRITICAL
        elif AlertLevel.WARNING in levels:
            self.overall_level = AlertLevel.WARNING
        else:
            self.overall_level = AlertLevel.OK


# ──────────────────────────────────────────────
# System Information Collectors
# ──────────────────────────────────────────────

class SystemCollector:
    """جمع معلومات النظام الأساسية"""

    @staticmethod
    def get_hostname() -> str:
        return socket.gethostname()

    @staticmethod
    def get_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_os_info() -> str:
        return f"{platform.system()} {platform.release()}"

    @staticmethod
    def get_kernel() -> str:
        return platform.release()

    @staticmethod
    def get_uptime() -> str:
        try:
            with open("/proc/uptime", "r") as f:
                uptime_seconds = float(f.readline().split()[0])
            delta = timedelta(seconds=int(uptime_seconds))
            days = delta.days
            hours, remainder = divmod(delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            return f"{days}d {hours}h {minutes}m"
        except FileNotFoundError:
            return "N/A"


# ──────────────────────────────────────────────
# Metric Collectors
# ──────────────────────────────────────────────

class MetricCollector:
    """جمع مقاييس الأداء"""

    @staticmethod
    def check_cpu() -> MetricResult:
        try:
            load_1, load_5, load_15 = os.getloadavg()
            cpu_count = os.cpu_count() or 1
            usage_pct = (load_1 / cpu_count) * 100

            if usage_pct >= THRESHOLDS["cpu_critical"]:
                level = AlertLevel.CRITICAL
                msg = f"استخدام المعالج مرتفع جداً: {usage_pct:.1f}%"
            elif usage_pct >= THRESHOLDS["cpu_warning"]:
                level = AlertLevel.WARNING
                msg = f"استخدام المعالج مرتفع: {usage_pct:.1f}%"
            else:
                level = AlertLevel.OK
                msg = f"استخدام المعالج طبيعي: {usage_pct:.1f}%"

            return MetricResult("CPU", round(usage_pct, 1), "%", level, msg)
        except Exception as e:
            return MetricResult("CPU", 0, "%", AlertLevel.WARNING, f"خطأ: {e}")

    @staticmethod
    def check_memory() -> MetricResult:
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()

            mem_info = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = int(parts[1].strip().split()[0])
                    mem_info[key] = val

            total = mem_info.get("MemTotal", 1)
            available = mem_info.get("MemAvailable", 0)
            used_pct = ((total - available) / total) * 100

            if used_pct >= THRESHOLDS["memory_critical"]:
                level = AlertLevel.CRITICAL
                msg = f"الذاكرة ممتلئة تقريباً: {used_pct:.1f}%"
            elif used_pct >= THRESHOLDS["memory_warning"]:
                level = AlertLevel.WARNING
                msg = f"استخدام الذاكرة مرتفع: {used_pct:.1f}%"
            else:
                level = AlertLevel.OK
                msg = f"الذاكرة طبيعية: {used_pct:.1f}%"

            return MetricResult("Memory", round(used_pct, 1), "%", level, msg)
        except Exception as e:
            return MetricResult("Memory", 0, "%", AlertLevel.WARNING, f"خطأ: {e}")

    @staticmethod
    def check_disk(path: str = "/") -> MetricResult:
        try:
            stat = os.statvfs(path)
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bfree * stat.f_frsize
            used_pct = ((total - free) / total) * 100

            if used_pct >= THRESHOLDS["disk_critical"]:
                level = AlertLevel.CRITICAL
                msg = f"القرص ممتلئ تقريباً: {used_pct:.1f}%"
            elif used_pct >= THRESHOLDS["disk_warning"]:
                level = AlertLevel.WARNING
                msg = f"مساحة القرص منخفضة: {used_pct:.1f}%"
            else:
                level = AlertLevel.OK
                msg = f"مساحة القرص طبيعية: {used_pct:.1f}%"

            return MetricResult("Disk", round(used_pct, 1), "%", level, msg)
        except Exception as e:
            return MetricResult("Disk", 0, "%", AlertLevel.WARNING, f"خطأ: {e}")

    @staticmethod
    def check_load() -> MetricResult:
        try:
            load_1, load_5, load_15 = os.getloadavg()

            if load_1 >= THRESHOLDS["load_critical"]:
                level = AlertLevel.CRITICAL
            elif load_1 >= THRESHOLDS["load_warning"]:
                level = AlertLevel.WARNING
            else:
                level = AlertLevel.OK

            msg = f"Load: {load_1:.2f} / {load_5:.2f} / {load_15:.2f}"
            return MetricResult("Load", round(load_1, 2), "avg", level, msg)
        except Exception as e:
            return MetricResult("Load", 0, "avg", AlertLevel.WARNING, f"خطأ: {e}")


# ──────────────────────────────────────────────
# Service Checker
# ──────────────────────────────────────────────

class ServiceChecker:
    """فحص حالة الخدمات"""

    @staticmethod
    def check_service(name: str) -> ServiceStatus:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True, text=True, timeout=5
            )
            is_active = result.stdout.strip() == "active"
            return ServiceStatus(name=name, is_active=is_active)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ServiceStatus(name=name, is_active=False)


# ──────────────────────────────────────────────
# Report Generator
# ──────────────────────────────────────────────

class ReportGenerator:
    """توليد التقارير"""

    LEVEL_COLORS = {
        AlertLevel.OK: "\033[92m",
        AlertLevel.WARNING: "\033[93m",
        AlertLevel.CRITICAL: "\033[91m",
        AlertLevel.EMERGENCY: "\033[95m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    @classmethod
    def print_report(cls, report: HealthReport):
        """طباعة التقرير في Terminal"""
        w = 60
        level_color = cls.LEVEL_COLORS[report.overall_level]

        print()
        print(f"{cls.BOLD}{'═' * w}")
        print(f"  SERVER HEALTH REPORT")
        print(f"{'═' * w}{cls.RESET}")
        print()
        print(f"  {cls.DIM}Hostname:{cls.RESET}  {report.hostname}")
        print(f"  {cls.DIM}IP:{cls.RESET}        {report.ip_address}")
        print(f"  {cls.DIM}OS:{cls.RESET}        {report.os_info}")
        print(f"  {cls.DIM}Uptime:{cls.RESET}    {report.uptime}")
        print(f"  {cls.DIM}Time:{cls.RESET}      {report.timestamp:%Y-%m-%d %H:%M:%S}")
        print(f"  {cls.DIM}Status:{cls.RESET}    {level_color}{cls.BOLD}"
              f"{report.overall_level.value}{cls.RESET}")
        print()
        print(f"{cls.BOLD}  {'─' * (w - 4)}")
        print(f"  METRICS{cls.RESET}")
        print()

        for m in report.metrics:
            color = cls.LEVEL_COLORS[m.level]
            icon = "✓" if m.level == AlertLevel.OK else "⚠" if m.level == AlertLevel.WARNING else "✗"
            bar_len = 30
            filled = int((m.value / 100) * bar_len) if m.unit == "%" else 0
            bar = f"{'█' * filled}{'░' * (bar_len - filled)}"

            print(f"  {color}{icon}{cls.RESET} {m.name:8s}  "
                  f"{color}{bar}{cls.RESET}  "
                  f"{cls.BOLD}{m.value:6.1f}{m.unit}{cls.RESET}")

        print()
        print(f"{cls.BOLD}  {'─' * (w - 4)}")
        print(f"  SERVICES{cls.RESET}")
        print()

        for s in report.services:
            if s.is_active:
                print(f"  {cls.LEVEL_COLORS[AlertLevel.OK]}●{cls.RESET} "
                      f"{s.name:20s} {cls.LEVEL_COLORS[AlertLevel.OK]}active{cls.RESET}")
            else:
                print(f"  {cls.LEVEL_COLORS[AlertLevel.CRITICAL]}●{cls.RESET} "
                      f"{s.name:20s} {cls.LEVEL_COLORS[AlertLevel.CRITICAL]}inactive{cls.RESET}")

        print()
        print(f"{cls.BOLD}{'═' * w}{cls.RESET}")
        print()

    @staticmethod
    def save_json(report: HealthReport, path: str):
        """حفظ التقرير كملف JSON"""
        data = {
            "hostname": report.hostname,
            "ip_address": report.ip_address,
            "os_info": report.os_info,
            "uptime": report.uptime,
            "timestamp": report.timestamp.isoformat(),
            "overall_level": report.overall_level.value,
            "metrics": [m.to_dict() for m in report.metrics],
            "services": [
                {"name": s.name, "is_active": s.is_active}
                for s in report.services
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  📄 Report saved: {path}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    print("\n  🔍 Collecting system metrics...\n")

    # Collect system info
    sys_collector = SystemCollector()
    hostname = sys_collector.get_hostname()
    ip = sys_collector.get_ip()
    os_info = sys_collector.get_os_info()
    kernel = sys_collector.get_kernel()
    uptime = sys_collector.get_uptime()

    # Collect metrics
    metric_collector = MetricCollector()
    metrics = [
        metric_collector.check_cpu(),
        metric_collector.check_memory(),
        metric_collector.check_disk("/"),
        metric_collector.check_load(),
    ]

    # Check services
    service_checker = ServiceChecker()
    services = [
        service_checker.check_service(svc)
        for svc in MONITORED_SERVICES
    ]

    # Build report
    report = HealthReport(
        hostname=hostname,
        ip_address=ip,
        os_info=os_info,
        kernel=kernel,
        uptime=uptime,
        timestamp=datetime.now(),
        metrics=metrics,
        services=services,
    )
    report.calculate_overall()

    # Output
    ReportGenerator.print_report(report)

    # Save JSON report
    output_dir = os.path.expanduser("~/health-reports")
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(
        output_dir, f"health_{datetime.now():%Y%m%d_%H%M%S}.json"
    )
    ReportGenerator.save_json(report, json_path)


if __name__ == "__main__":
    main()
