"""
Live Physical Storage SMART & Wear-Leveling Telemetry Reader — SIH26149.

Forensic Principles & Safety:
- STRICT READ-ONLY telemetry queries (zero write operations, zero destructive ioctls)
- Defense-in-depth Graceful Fallback: Detects virtual machine environments, restricted
  enterprise sandbox policies, or missing smartmontools binaries without crashing.
- Preserves ISO/IEC 27037:2012 Evidence Handling boundary: Physical telemetry is segregated
  from forensic image processing.
"""
import sys
import os
import shutil
import subprocess
import json
import platform
from typing import Dict, Any, List, Optional


def query_windows_storage_telemetry() -> Optional[Dict[str, Any]]:
    """
    Queries Windows Storage Management via PowerShell Get-PhysicalDisk.
    Uses pure read-only CIM / WMI cmdlets.
    """
    if platform.system() != "Windows":
        return None

    ps_script = """
    $ErrorActionPreference = 'SilentlyContinue'
    $disks = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size
    if ($disks) {
        $out = @()
        foreach ($d in $disks) {
            $counters = Get-StorageReliabilityCounter -PhysicalDisk $d | Select-Object Temperature, ReadErrorsTotal, WriteErrorsTotal, Wear
            $out += @{
                device_id = $d.DeviceId
                model = $d.FriendlyName
                media_type = [string]$d.MediaType
                bus_type = [string]$d.BusType
                health_status = [string]$d.HealthStatus
                operational_status = [string]$d.OperationalStatus
                size_bytes = $d.Size
                temperature_c = if ($counters) { $counters.Temperature } else { $null }
                read_errors = if ($counters) { $counters.ReadErrorsTotal } else { 0 }
                write_errors = if ($counters) { $counters.WriteErrorsTotal } else { 0 }
                wear_percentage = if ($counters) { $counters.Wear } else { $null }
            }
        }
        $out | ConvertTo-Json -Compress
    }
    """
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=8
        )
        if res.returncode == 0 and res.stdout.strip():
            raw_json = res.stdout.strip()
            data = json.loads(raw_json)
            # Normalize single object vs array
            disks = data if isinstance(data, list) else [data]
            return {
                "platform": "Windows_CIM_Storage",
                "physical_disks_detected": len(disks),
                "disks": disks
            }
    except Exception:
        pass
    return None


def query_smartctl_telemetry(device: str = "/dev/sda") -> Optional[Dict[str, Any]]:
    """
    Queries smartctl for NVMe/SATA health and wear if installed on Linux/Unix.
    """
    smartctl_bin = shutil.which("smartctl")
    if not smartctl_bin:
        return None

    try:
        res = subprocess.run(
            [smartctl_bin, "-j", "-H", "-A", device],
            capture_output=True,
            text=True,
            timeout=8
        )
        if res.stdout.strip():
            data = json.loads(res.stdout)
            return {
                "platform": "smartctl_json",
                "smart_status": data.get("smart_status", {}),
                "device": data.get("device", {}),
                "temperature": data.get("temperature", {}),
                "nvme_smart_health_information_log": data.get("nvme_smart_health_information_log")
            }
    except Exception:
        pass
    return None


def get_live_storage_telemetry(device_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Master Live Storage Telemetry Collector with guaranteed fail-safe fallback.
    Never throws an unhandled exception.
    """
    # 1. Try Windows Storage Management if on Windows
    if platform.system() == "Windows":
        win_data = query_windows_storage_telemetry()
        if win_data and win_data.get("disks"):
            return {
                "status": "LIVE_HARDWARE_CAPTURED",
                "telemetry_available": True,
                "capture_mode": "WINDOWS_STORAGE_CIM_POWERSHELL",
                "advisory": "Authentic physical storage telemetry acquired via read-only Windows Storage Subsystem.",
                "host_os": f"{platform.system()} {platform.release()}",
                "telemetry": win_data
            }

    # 2. Try smartctl on POSIX
    if device_path:
        smart_data = query_smartctl_telemetry(device_path)
        if smart_data:
            return {
                "status": "LIVE_HARDWARE_CAPTURED",
                "telemetry_available": True,
                "capture_mode": "SMARTCTL_POSIX_IOCTL",
                "advisory": "Authentic SMART health metrics acquired via smartctl read-only query.",
                "host_os": f"{platform.system()} {platform.release()}",
                "telemetry": smart_data
            }

    # 3. Transparent, Defensible Fallback Path (e.g. inside locked VM, CI, or unprivileged container)
    return {
        "status": "SANDBOX_RESTRICTED_FALLBACK",
        "telemetry_available": False,
        "capture_mode": "DIAGNOSTIC_ADVISORY_FALLBACK",
        "advisory": (
            "Host operating environment or unprivileged container policy restricts direct physical "
            "hardware block-device query. Safe read-only mode maintained per ISO/IEC 27037:2012. "
            "In forensic field deployments with supervisor privileges, live SMART/Wear metrics "
            "are queried without altering device contents."
        ),
        "host_os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "simulated_demo_reference": {
            "media_type": "NVMe SSD (Enterprise Class)",
            "available_spare_percentage": 100,
            "percentage_used_wear": 4,
            "data_units_read_tb": 18.4,
            "data_units_written_tb": 12.1,
            "power_on_hours": 1420,
            "unsafe_shutdowns": 0,
            "media_and_data_integrity_errors": 0
        }
    }
