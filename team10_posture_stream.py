import os
import sys
import json
from datetime import datetime, timezone
from kafka import KafkaConsumer

# Configuration
KAFKA_BOOTSTRAP_SERVERS = ['localhost:9092']
POSTURE_TOPIC = ['posture-events']
# Forces the JSON file to save in the exact same folder as this Python script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_FILE = os.path.join(SCRIPT_DIR, "team10_alerts.json")

# Baseline Configuration
APPROVED_PROCESSES = ["chrome.exe", "svchost.exe", "explorer.exe", "csagent.exe"]

def append_to_dashboard(alert_name, severity, details):
    """Saves the alert to the unified JSON file for the HTML dashboard."""
    try:
        events_list = []
        if os.path.exists(DASHBOARD_FILE):
            try:
                with open(DASHBOARD_FILE, 'r', encoding='utf-8') as f:
                    events_list = json.load(f)
            except Exception:
                events_list = []
                
        alert_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_name": alert_name,
            "severity": severity,
            "details": details
        }
        
        events_list.insert(0, alert_record)
        events_list = events_list[:50]
        
        with open(DASHBOARD_FILE, 'w', encoding='utf-8') as f:
            json.dump(events_list, f, indent=4)
    except Exception as e:
        print(f"[ERROR] Failed to write to dashboard file: {e}")

def alert_soc(alert_name, severity, details):
    """Formats and prints critical alerts, AND saves them to the dashboard."""
    print("\n" + "!"*65)
    print(f"[+] NEW {severity} POSTURE ALERT: {alert_name}")
    print("!"*65)
    for key, value in details.items():
        print(f"    - {key}: {value}")
    print("!"*65 + "\n")
    append_to_dashboard(alert_name, severity, details)

# ==========================================
# CORRELATION ENGINES
# ==========================================

def corr_01_edr_tampering(software_list, service_list, endpoint_id):
    security_tools = ["CrowdStrike", "Windows Defender", "SentinelOne", "Carbon Black", "McAfee"]
    for software in software_list:
        if any(tool.lower() in software.get("name", "").lower() for tool in security_tools):
            service_found = False
            for svc in service_list:
                if svc.get("display_name") == software.get("name"):
                    service_found = True
                    if svc.get("state") != "Running":
                        alert_soc(
                            "EDR Tampering Detected", "CRITICAL",
                            {
                                "Endpoint": endpoint_id,
                                "Target Tool": software.get("name"),
                                "Service State": svc.get("state"),
                                "Narrative": "Security tool is installed but its background service has been stopped. An attacker may have killed the process."
                            }
                        )
            if not service_found:
                alert_soc(
                    "EDR Service Unhooking", "CRITICAL",
                    {
                        "Endpoint": endpoint_id,
                        "Target Tool": software.get("name"),
                        "Narrative": "Security tool is installed but no matching background service exists in memory."
                    }
                )

def corr_02_unquoted_service_path(service_list, endpoint_id):
    for svc in service_list:
        path = svc.get("path", "")
        if " " in path and not path.startswith('"'):
            alert_soc(
                "Unquoted Service Path Vulnerability", "HIGH",
                {
                    "Endpoint": endpoint_id,
                    "Vulnerable Service": svc.get("service_name"),
                    "Broken Path": path,
                    "Narrative": "Service execution path contains spaces but lacks quotes. This endpoint is highly vulnerable to local Privilege Escalation."
                }
            )

def corr_03_rogue_listening_ports(port_list, endpoint_id):
    for port_data in port_list:
        process = port_data.get("process_name", "UNKNOWN")
        if process not in APPROVED_PROCESSES:
            alert_soc(
                "Rogue Listening Port (Shadow IT / C2)", "HIGH",
                {
                    "Endpoint": endpoint_id,
                    "Unapproved Process": process,
                    "Listening Port": str(port_data.get("port")),
                    "PID": str(port_data.get("pid")),
                    "Narrative": "An unknown executable has opened a network port. Possible Command & Control beaconing or unauthorized software."
                }
            )

def corr_04_software_services_mapping(software_list, service_list, endpoint_id):
    """MIGRATED: Maps installed software to actively running Windows Services."""
    installed_apps = [str(app.get("name", "")).strip() for app in software_list if app.get("name")]
    running_services = [str(svc.get("display_name", "")).strip() for svc in service_list if svc.get("display_name")]

    active_software_services = []
    for app in installed_apps:
        if any(app.lower() in svc.lower() for svc in running_services):
            active_software_services.append(app)

    # Deduplicate
    active_software_services = list(set(active_software_services))

    if active_software_services:
        alert_soc(
            "Software-to-Service Mapping", "INFO",
            {
                "Endpoint": endpoint_id,
                "Mapped Services Count": str(len(active_software_services)),
                "Examples": ", ".join(active_software_services[:3]),
                "Narrative": "System Context: Correlated installed applications that are actively running as background services."
            }
        )

def corr_05_persistence_overlap(task_list, autorun_dict, endpoint_id):
    """MIGRATED: Cross-references Scheduled Tasks and Autoruns for overlapping persistence."""
    if not isinstance(autorun_dict, dict):
        return

    # Flatten autorun registry values into one string for easy searching
    run_1 = str(autorun_dict.get("current_version_run", "")).lower()
    run_2 = str(autorun_dict.get("current_version_runonce", "")).lower()
    run_3 = str(autorun_dict.get("wow6432node_run", "")).lower()
    run_4 = str(autorun_dict.get("user_run", "")).lower()
    combined_autoruns = run_1 + run_2 + run_3 + run_4

    task_names = []
    for task in task_list:
        name = str(task.get("TaskName", "")).lower().strip()
        if name and len(name) > 4:
            task_names.append(name)

    multi_layer_persistence = []
    for name in set(task_names):
        if name in combined_autoruns:
            multi_layer_persistence.append(name)

    if multi_layer_persistence:
        alert_soc(
            "Multi-Layer Persistence Overlap", "HIGH",
            {
                "Endpoint": endpoint_id,
                "Suspicious Items": ", ".join(multi_layer_persistence),
                "Narrative": "A program is utilizing multi-layered persistence by registering as BOTH a Scheduled Task and a Registry Autorun. Highly indicative of malware."
            }
        )

def process_posture_snapshot(snapshot):
    """Parses the incoming Kafka payload and runs all 5 correlations."""
    endpoint_id = snapshot.get("endpoint_id", "UNKNOWN_ENDPOINT")
    software_list = snapshot.get("installed_software", [])
    service_list = snapshot.get("active_services", [])
    port_list = snapshot.get("active_ports", [])
    task_list = snapshot.get("scheduled_tasks", [])
    autorun_dict = snapshot.get("registry_autoruns", {})

    print(f"[*] Received Posture Snapshot from {endpoint_id}. Running Active Scan...")
    
    corr_01_edr_tampering(software_list, service_list, endpoint_id)
    corr_02_unquoted_service_path(service_list, endpoint_id)
    corr_03_rogue_listening_ports(port_list, endpoint_id)
    corr_04_software_services_mapping(software_list, service_list, endpoint_id)
    corr_05_persistence_overlap(task_list, autorun_dict, endpoint_id)

def start_engine():
    print("=====================================================")
    print("TEAM 10 POSTURE & COMPLIANCE ENGINE (KAFKA STREAM)")
    print("=====================================================")
    print(f"[*] Connecting to Broker: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"[*] Listening to Topic:   {POSTURE_TOPIC}")
    print("[*] Loaded 5 Active Correlation Rules.\n")

    try:
        consumer = KafkaConsumer(
            *POSTURE_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest'
        )
    except Exception as e:
        print(f"[!] Failed to connect to Kafka: {e}")
        sys.exit(1)

    print("[+] Stream connected. Waiting for endpoint snapshots...\n")

    try:
        for message in consumer:
            process_posture_snapshot(message.value)
    except KeyboardInterrupt:
        print("\n[*] Engine shut down by user.")
    finally:
        consumer.close()

if __name__ == "__main__":
    start_engine()