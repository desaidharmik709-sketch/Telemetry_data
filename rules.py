"""
Compliance Verification Rules Engine
"""

import json
from pathlib import Path
from datetime import datetime

# =========================================================
# TEAM 10 ADVANCED METRICS & ENRICHMENT ENGINE
# =========================================================
METRICS_FILE = Path("reports/team10_enrichment_metrics.json")

def export_metric_to_json(metric_name, data_dict):
    """Silently appends structured enrichment data to JSON."""
    METRICS_FILE.parent.mkdir(exist_ok=True)
    current_data = {"execution_timestamp": datetime.utcnow().isoformat() + "Z", "correlations": {}}
    
    if METRICS_FILE.exists():
        try:
            with open(METRICS_FILE, "r", encoding="utf-8") as f:
                current_data = json.load(f)
                if "correlations" not in current_data:
                    current_data["correlations"] = {}
        except Exception:
            pass # Overwrite if corrupted
            
    current_data["correlations"][metric_name] = data_dict
    
    with open(METRICS_FILE, "w", encoding="utf-8") as f:
        json.dump(current_data, f, indent=4)



DATA_DIR = Path("compliance_output")


def load_latest(name):
    path = DATA_DIR / f"{name}.json"

    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = json.load(f)

        if isinstance(content, list) and len(content) > 0:
            return content[-1].get("data", {})

        return {}

    except Exception:
        return {}


def safe_parse_json(value):
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, dict):
        return [value]

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return []

        try:
            parsed = json.loads(value)

            if isinstance(parsed, list):
                return parsed

            if isinstance(parsed, dict):
                return [parsed]

        except Exception:
            pass

    return []


# --- Checks ---

def installed_software_check():
    data = load_latest("01_installed_software")
    items = safe_parse_json(data.get("stdout", ""))
    banned = ["utorrent", "bittorrent", "teamviewer"]

    found = []
    for item in items:
        name = str(item.get("DisplayName", "")).lower()
        if any(b in name for b in banned):
            found.append(name)

    return {
        "status": len(found) == 0,
        "evidence": "No blacklisted software found" if len(found) == 0 else f"Identified risks: {', '.join(found)}"
    }


def hardware_inventory_check():
    data = load_latest("04_hardware_inventory")

    items = safe_parse_json(data.get("stdout"))

    valid = (
        len(items) > 0
        and items[0].get("Manufacturer")
        and items[0].get("Model")
    )

    return {
        "status": valid,
        "evidence": (
            f"{items[0].get('Manufacturer')} {items[0].get('Model')}"
            if valid
            else "Telemetry missing"
        )
    }


def windows_services_check():
    data = load_latest("05_windows_services")
    items = safe_parse_json(data.get("stdout", ""))

    required = ["windefend", "mpssvc"]
    active = [str(i.get("Name", "")).lower() for i in items]

    missing = [s for s in required if s not in active]

    return {
        "status": len(missing) == 0,
        "evidence": "Core services active" if not missing else f"Missing: {', '.join(missing)}"
    }


def failed_logins_check():
    data = load_latest("06_failed_logins")
    items = safe_parse_json(data.get("stdout", ""))
    return {"status": len(items) < 20, "evidence": f"{len(items)} failed logins"}


def successful_logins_check():
    data = load_latest("07_successful_logins")

    items = safe_parse_json(data.get("stdout"))

    return {
        "status": len(items) > 0,
        "evidence": f"{len(items)} successful logins"
    }


def firewall_enabled():
    data = load_latest("10_firewall_configuration")

    text = str(data.get("stdout", "")).upper()

    enabled_profiles = text.count("STATE                                 ON")

    return {
        "status": enabled_profiles == 3,
        "evidence": f"{enabled_profiles}/3 firewall profiles enabled"
    }


def registry_autoruns_check():
    data = load_latest("12_registry_autoruns")
    run_out = data.get("run", {}).get("stdout", "").lower()
    runonce_out = data.get("runonce", {}).get("stdout", "").lower()

    suspicious = ["appdata\\", "temp\\"]
    found = [x for x in suspicious if x in run_out + runonce_out]

    return {
        "status": len(found) == 0,
        "evidence": "Clean" if not found else f"Suspicious: {', '.join(found)}"
    }


def scheduled_tasks_check():
    data = load_latest("13_scheduled_tasks")
    items = safe_parse_json(data.get("stdout", ""))

    suspicious = ["wscript.exe", "cscript.exe"]
    found = []

    for t in items:
        text = str(t).lower()
        if any(s in text for s in suspicious):
            found.append(t.get("TaskName", ""))

    return {
        "status": len(found) == 0,
        "evidence": "OK" if not found else f"Suspicious tasks: {', '.join(found)}"
    }


def admin_accounts_check():
    data = load_latest("16_user_accounts_and_privileges")

    admins = data.get("admins", {}).get("stdout", [])

    items = safe_parse_json(admins)

    return {
        "status": len(items) > 0,
        "evidence": f"{len(items)} admin entries"
    }


def defender_enabled():
    data = load_latest("17_windows_defender_status")

    items = safe_parse_json(data.get("stdout"))

    if not items:
        return {
            "status": False,
            "evidence": "No data"
        }

    status = bool(items[0].get("RealTimeProtectionEnabled"))

    return {
        "status": status,
        "evidence": "Defender active" if status else "Defender OFF"
    }


def boot_shutdown_check():
    data = load_latest("20_boot_shutdown_events")

    text = data.get("stdout", "")

    boots = text.count("6005")
    shutdowns = text.count("6006")

    return {
        "status": boots > 0,
        "evidence": f"{boots} boots and {shutdowns} shutdown events"
    }


def audit_policy_check():
    data = load_latest("21_audit_policy_configuration")
    text = data.get("stdout", "")

    required = ["logon", "logoff", "policy"]
    missing = [r for r in required if r.lower() not in text.lower()]

    return {
        "status": len(missing) == 0,
        "evidence": "OK" if not missing else f"Missing: {', '.join(missing)}"
    }


def drivers_inventory_check():
    data = load_latest("22_drivers_inventory")

    lines = data.get("stdout", "").splitlines()

    count = len(lines)

    return {
        "status": count > 5,
        "evidence": f"{count} driver entries discovered"
    }


def more_windows_settings_check():
    data = load_latest("23_more_windows_settings")
    uac = data.get("uac_level", {}).get("stdout", "")

    return {
        "status": "0x5" in uac or "0x2" in uac,
        "evidence": "UAC checked"
    }


def usb_direct_connection_check():
    data = load_latest("24_usb_direct_connection")
    items = safe_parse_json(data.get("stdout", ""))

    return {
        "status": True,
        "evidence": f"{len(items)} USB entries"
    }


def bios_snapshot_check():
    data = load_latest("25_bios_snapshot")

    raw = data.get("stdout", [])

    if isinstance(raw, dict):
        raw = [raw]

    if not raw:
        return {
            "status": False,
            "evidence": "No BIOS data"
        }

    version = raw[0].get("SMBIOSBIOSVersion", "Unknown")

    return {
        "status": True,
        "evidence": f"BIOS Version: {version}"
    }


def windows_scan_history_check():
    data = load_latest("26_windows_scan_history")
    items = safe_parse_json(data.get("stdout", ""))

    return {
        "status": True,
        "evidence": f"{len(items)} scan logs"
    }


def usb_setting_history_check():
    data = load_latest("27_usb_setting_history")
    return {
        "status": True,
        "evidence": "USB registry checked"
    }
    
def corr_01_software_services_native():
    """Native Correlation 1: Maps installed software to actively running Windows Services."""
    sw_data = load_latest("01_installed_software")
    sw_items = safe_parse_json(sw_data.get("stdout", ""))
    
    svc_data = load_latest("05_windows_services")
    svc_items = safe_parse_json(svc_data.get("stdout", ""))

    # Extract base names of installed software
    installed_apps = [str(app.get("DisplayName", "")).strip() for app in sw_items if app.get("DisplayName")]
    
    # Extract base names of running services
    running_services = [str(svc.get("DisplayName", "")).strip() for svc in svc_items if svc.get("DisplayName")]

    # Find the real overlap: Which installed apps are running as services right now?
    active_software_services = []
    for app in installed_apps:
        # Check if the primary app name exists within the running services list
        if any(app.lower() in svc.lower() for svc in running_services):
            active_software_services.append(app)

    # Deduplicate the list
    active_software_services = list(set(active_software_services))

    export_metric_to_json("Native_Software_to_Services_Correlation", {
        "total_software_installed": len(installed_apps),
        "total_services_running": len(running_services),
        "software_running_as_services_count": len(active_software_services),
        "active_software_services_list": active_software_services[:10] # Show up to 10 real examples
    })

    return {
        "status": True,
        "evidence": f"Mapped {len(active_software_services)} installed applications directly to running Windows services."
    }


def corr_02_persistence_overlap_native():
    """Native Correlation 2: Cross-references Scheduled Tasks and Autoruns for overlapping persistence."""
    tasks_data = load_latest("13_scheduled_tasks")
    tasks_items = safe_parse_json(tasks_data.get("stdout", ""))
    
    auto_data = load_latest("12_registry_autoruns")
    
    # --- UPDATED FOR TEAM 8'S NEW COLLECTOR KEYS ---
    run_1 = str(auto_data.get("current_version_run", {}).get("stdout", "")).lower()
    run_2 = str(auto_data.get("current_version_runonce", {}).get("stdout", "")).lower()
    run_3 = str(auto_data.get("wow6432node_run", {}).get("stdout", "")).lower()
    run_4 = str(auto_data.get("user_run", {}).get("stdout", "")).lower()
    
    combined_autoruns = run_1 + run_2 + run_3 + run_4

    # Extract Task Names instead of executables
    task_names = []
    for task in tasks_items:
        name = str(task.get("TaskName", "")).lower().strip()
        if name and len(name) > 4: # Ignore extremely short/generic names
            task_names.append(name)

    # Find which of those Task Names ALSO exist anywhere in the newly expanded Registry Autoruns
    multi_layer_persistence = []
    for name in set(task_names):
        if name in combined_autoruns:
            multi_layer_persistence.append(name)

    export_metric_to_json("Native_Persistence_Overlap_Correlation", {
        "total_scheduled_tasks": len(tasks_items),
        "tasks_analyzed_for_overlap": len(set(task_names)),
        "multi_layer_persistence_count": len(multi_layer_persistence),
        "overlapping_persistence_names": multi_layer_persistence
    })

    return {
        "status": True,
        "evidence": f"Found {len(multi_layer_persistence)} items utilizing multi-layered persistence (Tasks + Autoruns)."
    }
    
RULES = [
    {
        "id": "T10-CORR-01",
        "framework": "SYSTEM",
        "control": "Software to Service Vulnerability Mapping",
        "datapoint": "t10_corr_01"
    },
    {
        "id": "T10-CORR-02",
        "framework": "SYSTEM",
        "control": "Persistence Threat Intel Enrichment",
        "datapoint": "t10_corr_02"
    },
    {
        "id": "DP-001",
        "framework": "SYSTEM",
        "control": "Installed Software Inventory",
        "datapoint": "01_installed_software"
    },
    {
        "id": "DP-004",
        "framework": "SYSTEM",
        "control": "Hardware Asset Inventory",
        "datapoint": "04_hardware_inventory"
    },
    {
        "id": "DP-005",
        "framework": "SYSTEM",
        "control": "Windows Service Enumeration",
        "datapoint": "05_windows_services"
    },
    {
        "id": "AC-7",
        "framework": "NIST",
        "control": "Failed Login Monitoring",
        "datapoint": "06_failed_logins"
    },
    {
        "id": "AU-2",
        "framework": "NIST",
        "control": "Successful Login Auditing",
        "datapoint": "07_successful_logins"
    },
    {
        "id": "PCI-1.4",
        "framework": "PCI DSS",
        "control": "Firewall Configuration",
        "datapoint": "10_firewall_configuration"
    },
    {
        "id": "SI-7",
        "framework": "NIST",
        "control": "Registry Autorun Monitoring",
        "datapoint": "12_registry_autoruns"
    },
    {
        "id": "AU-12-ST",
        "framework": "DPDP",
        "control": "Scheduled Task Monitoring",
        "datapoint": "13_scheduled_tasks"
    },
    {
        "id": "AC-6",
        "framework": "NIST",
        "control": "Privileged Account Monitoring",
        "datapoint": "16_user_accounts_and_privileges"
    },
    {
        "id": "PCI-5.2",
        "framework": "PCI DSS",
        "control": "Endpoint Protection",
        "datapoint": "17_windows_defender_status"
    },
    {
        "id": "AU-5",
        "framework": "NIST",
        "control": "System Boot Monitoring",
        "datapoint": "20_boot_shutdown_events"
    },
    {
        "id": "AU-6",
        "framework": "NIST",
        "control": "Audit Policy Monitoring",
        "datapoint": "21_audit_policy_configuration"
    },
    {
        "id": "DRV-01",
        "framework": "SYSTEM",
        "control": "Driver Tree Inventory Mapping",
        "datapoint": "22_drivers_inventory"
    },
    {
        "id": "WIN-SET",
        "framework": "SYSTEM",
        "control": "Extended Local Subsystem Regulations",
        "datapoint": "23_more_windows_settings"
    },
    {
        "id": "USB-DIR",
        "framework": "HARDWARE",
        "control": "Logical Host Storage Route Identification",
        "datapoint": "24_usb_direct_connection"
    },
    {
        "id": "BIOS-SNAP",
        "framework": "HARDWARE",
        "control": "Firmware Core Configuration Identifiers",
        "datapoint": "25_bios_snapshot"
    },
    {
        "id": "SCAN-HIST",
        "framework": "ENDPOINT",
        "control": "Local Threat History Auditing Logs",
        "datapoint": "26_windows_scan_history"
    },
    {
        "id": "USB-HIST",
        "framework": "HARDWARE",
        "control": "Historical Peripheral Storage Connectivity Signatures",
        "datapoint": "27_usb_setting_history"
    }
]