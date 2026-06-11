import json
import time
from rules import (
    RULES,
    corr_01_software_services,          
    corr_02_persistence_threat_intel,
    installed_software_check,
    hardware_inventory_check,
    windows_services_check,
    failed_logins_check,
    successful_logins_check,
    firewall_enabled,
    registry_autoruns_check,
    scheduled_tasks_check,
    admin_accounts_check,
    defender_enabled,
    boot_shutdown_check,
    audit_policy_check,
    drivers_inventory_check,
    more_windows_settings_check,
    usb_direct_connection_check,
    bios_snapshot_check,
    windows_scan_history_check,
    usb_setting_history_check
)

CHECKS = {
    "t10_corr_01": corr_01_software_services,        
    "t10_corr_02": corr_02_persistence_threat_intel,
    "01_installed_software": installed_software_check,
    "04_hardware_inventory": hardware_inventory_check,
    "05_windows_services": windows_services_check,
    "06_failed_logins": failed_logins_check,
    "07_successful_logins": successful_logins_check,
    "10_firewall_configuration": firewall_enabled,
    "12_registry_autoruns": registry_autoruns_check,
    "13_scheduled_tasks": scheduled_tasks_check,
    "16_user_accounts_and_privileges": admin_accounts_check,
    "17_windows_defender_status": defender_enabled,
    "20_boot_shutdown_events": boot_shutdown_check,
    "21_audit_policy_configuration": audit_policy_check,
    "22_drivers_inventory": drivers_inventory_check,
    "23_more_windows_settings": more_windows_settings_check,
    "24_usb_direct_connection": usb_direct_connection_check,
    "25_bios_snapshot": bios_snapshot_check,
    "26_windows_scan_history": windows_scan_history_check,
    "27_usb_setting_history": usb_setting_history_check
}

def evaluate():
    findings = []
    for rule in RULES:
        # Prevent continuous loop processing from generating short processing spikes
        time.sleep(0.1)
        datapoint = rule["datapoint"]
        if datapoint not in CHECKS:
            findings.append({
                "id": rule["id"],
                "framework": rule["framework"],
                "control": rule["control"],
                "status": "MANUAL REVIEW",
                "evidence": f"Missing engine verification logic mapping for {datapoint}"
            })
            continue
        try:
            result = CHECKS[datapoint]()
            findings.append({
                "id": rule["id"],
                "framework": rule["framework"],
                "control": rule["control"],
                "status": "PASS" if result.get("status", False) else "FAIL",
                "evidence": result.get("evidence", "No criteria matched")
            })
        except Exception as e:
            findings.append({
                "id": rule["id"],
                "framework": rule["framework"],
                "control": rule["control"],
                "status": "ERROR",
                "evidence": str(e)
            })
    print(f"[*] Evaluation completed for {len(findings)} technical checks.")
    return findings

if __name__ == "__main__":
    evaluate()