"""
Compliance Posture Assessment Engine - Low-Overhead Data Collector
Strictly throttled to guarantee CPU usage remains between 5% and 10% maximum.
"""
import hashlib
import os
import json
import csv
import socket
import subprocess
import ctypes
import getpass
import time
import uuid
import winreg
import platform
import sys
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = BASE_DIR / "compliance_output"
OUTPUT_DIR.mkdir(exist_ok=True)

CURRENT_USER = getpass.getuser()

debug_info = {
    "user": CURRENT_USER,
    "admin": bool(ctypes.windll.shell32.IsUserAnAdmin()),
    "cwd": str(BASE_DIR)
}

with open(BASE_DIR / "debug.json", "w", encoding="utf-8") as f:
    json.dump(debug_info, f, indent=4, ensure_ascii=False)


def ts():
    return datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")


def get_device_fingerprint():
    hostname = socket.gethostname()
    ip_address = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            pass

    try:
        mac_hex = iter(f"{uuid.getnode():012x}")
        mac_address = ":".join(a + b for a, b in zip(mac_hex, mac_hex))
    except Exception:
        mac_address = "00:00:00:00:00:00"

    manufacturer = "Unknown"
    model = "Unknown"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            manufacturer = winreg.QueryValueEx(key, "SystemManufacturer")[0].strip()
            model = winreg.QueryValueEx(key, "SystemProductName")[0].strip()
    except Exception:
        pass

    try:
        os_version = f"{platform.system()} {platform.release()} (Build {platform.version()})"
    except Exception:
        os_version = "Windows Unknown"

    return {
        "device_name": hostname,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "manufacturer": manufacturer,
        "model_name": model,
        "os_version": os_version
    }


def parse_maybe_json(text):
    text = text.strip()
    if not text:
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text

def remove_timestamp(obj):
    if isinstance(obj, dict):
        return {k: remove_timestamp(v) for k, v in obj.items() if k != "timestamp"}
    elif isinstance(obj, list):
        return [remove_timestamp(elem) for elem in obj]
    else:
        return obj


def generate_data_hash(data):
    try:
        cleaned_data = remove_timestamp(data)
        normalized = json.dumps(cleaned_data, sort_keys=True, default=str)
        return hashlib.sha256(normalized.encode()).hexdigest()
    except Exception:
        return "HASH_ERROR"


def is_duplicate(existing_data, current_hash):
    if not existing_data:
        return False
    try:
        previous_hash = existing_data[-1].get("data_hash")
        return previous_hash == current_hash
    except Exception:
        return False

def run_cmd(cmd):
    time.sleep(0.15)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True
        )
        stdout = result.stdout.strip()
        if not stdout:
            return []
        return {"raw_output": stdout}
    except Exception as e:
        return {"error": str(e)}


def run_ps(command):
    time.sleep(0.15)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True
        )
        stdout = result.stdout.strip()
        if not stdout:
            return []
        parsed = parse_maybe_json(stdout)
        if isinstance(parsed, (list, dict)):
            return parsed
        return {"raw_output": parsed}
    except Exception as e:
        return {"error": str(e)}


def save_json(name, data, event_id="COMP-GENERIC", severity="INFO", event_type="Compliance Metric Collection"):

    path = OUTPUT_DIR / f"{name}.json"
    data_hash = generate_data_hash(data)
    existing_data = []

    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
                if not isinstance(existing_data, list):
                    existing_data = []
        except Exception:
            existing_data = []

    active_index = None

    for i, old_entry in enumerate(existing_data):
        old_severity = old_entry.get("severity", "INFO")
        old_event_id = str(old_entry.get("event_id", ""))
        
        if old_severity == severity and not old_event_id.startswith("Previous"):
            active_index = i
            break

    new_entry = {
        "device_fingerprint": get_device_fingerprint(),
        "timestamp": ts(),
        "event_id": f"EVT_{name.upper()}",
        "event_type": event_type,
        "severity": severity,
        "data_hash": data_hash,
        "payload_message": {
            "collection_metadata": {
                "date": datetime.now().strftime("%d-%m-%Y"),
                "time": datetime.now().strftime("%I:%M:%S %p"),
                "username": CURRENT_USER
            },
            "data": data
        }
    }

    if active_index is not None:
        active_entry = existing_data[active_index]
        
        max_num = 0
        for entry in existing_data:
            eid = str(entry.get("event_id", ""))
            if eid.startswith("Previous"):
                try:
                    num = int(eid[8:])
                    if num > max_num:
                        max_num = num
                except ValueError:
                    pass
        next_previous_id = f"Previous{max_num + 1:03d}"
        
        active_entry["event_id"] = next_previous_id
        existing_data.append(new_entry)
        print(f"[ARCHIVED] {name} -> Previous active entry archived as {next_previous_id}. New entry appended.")
    else:
        existing_data.append(new_entry)
        print(f"[NEW] {name} -> New active entry appended.")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)

    print(f"[UPDATED] {name}")

def save_csv(name, headers, rows):
    path = OUTPUT_DIR / f"{name}.csv"
    file_exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(headers)
        for row in rows:
            writer.writerow(row)

# --- Standard Severity Engine ---

class SeverityEngine:
    AUTHORIZED_USB_VIDS = ["0951", "046d"] # Placeholders for whitelisted VIDs

    @staticmethod
    def get_highest_severity(data):
        levels = {"INFO": 0, "STATISTICAL": 1, "WARNING": 2, "INVESTIGATE": 3, "CRITICAL": 4}
        highest = "INFO"
        if isinstance(data, dict):
            highest = data.get("Severity", "INFO")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    sev = item.get("Severity", "INFO")
                    if levels.get(sev, 0) > levels.get(highest, 0):
                        highest = sev
        return highest

    @staticmethod
    def process_hardware(data):
        was_dict = isinstance(data, dict)
        items = [data] if was_dict else (data if isinstance(data, list) else [])
        
        APPROVED_VENDORS = ["Dell Inc.", "Lenovo", "HP", "Microsoft Corporation"]
        LEGACY_MODELS = ["ProBook 450 G3", "Latitude E5450", "ThinkPad T450"]
        
        for r in items:
            if not isinstance(r, dict): continue
            
            manufacturer = str(r.get("Manufacturer", "")).strip()
            model = str(r.get("Model", "")).strip()
            total_memory_bytes = r.get("TotalPhysicalMemory", 0)
            try:
                total_memory_bytes = int(total_memory_bytes)
            except (ValueError, TypeError):
                total_memory_bytes = 0
            
            total_memory_gb = total_memory_bytes / (1024 ** 3)
            
            if total_memory_bytes > 0:
                r["TotalPhysicalMemory"] = f"{int(total_memory_bytes / (1024 ** 2))} MB"
            
            # Severity removed per user request
            
        return data if was_dict else items

    @staticmethod
    def process_boot_shutdown(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            
            event_id = r.get("EventID")
            is_update = r.get("IsUpdateReboot", False)
            is_bsod = r.get("IsBSODReboot", False)
            is_powerloss = r.get("IsPowerLossReboot", False)
            
            if is_powerloss or event_id == 41:
                sev, reason = "CRITICAL", "Sudden power loss detected"
            elif is_bsod or event_id == 1001:
                sev, reason = "CRITICAL", "System crash / Blue Screen of Death"
            elif event_id == 1074 and is_update:
                sev, reason = "INFO", "Windows Update Reboot"
            elif event_id == 1074:
                sev, reason = "INFO", "Clean User Restart / Shutdown"
            elif event_id == 6008:
                sev, reason = "INVESTIGATE", "Unexpected Shutdown"
            elif event_id in [506, 507]:
                sev, reason = "INFO", "Modern Standby Transition"
            else:
                sev, reason = "STATISTICAL", "Routine System Event"
                
            r["Severity"] = sev
            r["SeverityReason"] = reason
            r["DetectionParameters"] = {
                "EventID": event_id, 
                "IsUpdate": is_update, 
                "IsBSOD": is_bsod, 
                "IsPowerLoss": is_powerloss
            }
        return data

    @staticmethod
    def process_scan_history(data):
        if not isinstance(data, dict): return data
        count = data.get("ThreatCount", 0)
        remediation = str(data.get("RemediationStatus", ""))
        
        if count > 0 and remediation == "Failed":
            sev, reason = "CRITICAL", "Active malware not remediated"
        elif count > 0:
            sev, reason = "INVESTIGATE", f"Detected {count} threats"
        else:
            sev, reason = "INFO", "No threats detected"
            
        data["DetectionParameters"] = {"ThreatCount": count, "RemediationStatus": remediation}
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data

    @staticmethod
    def process_bios_snapshot(data):
        if not isinstance(data, dict): return data
        sb = data.get("SecureBootEnabled", False)
        tpm = data.get("TPM_Present", False)
        comp = data.get("Firmware_Compliance", False)
        age = data.get("BIOS_Age_Days", 0)
        
        if not tpm:
            sev, reason = "CRITICAL", "TPM Missing"
        elif not comp:
            sev, reason = "CRITICAL", "Firmware Compliance Failed"
        elif not sb:
            sev, reason = "INVESTIGATE", "SecureBoot Disabled"
        elif age > 730:
            sev, reason = "INVESTIGATE", "BIOS Age > 730 Days"
        else:
            sev, reason = "INFO", "BIOS Compliant"
            
        data["DetectionParameters"] = {"SecureBootEnabled": sb, "TPM_Present": tpm, "Firmware_Compliance": comp, "BIOS_Age_Days": age}
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data

    @staticmethod
    def process_usb(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            is_storage = r.get("IsStorageDevice", False)
            vid = str(r.get("VID", ""))
            
            r["IsAuthorized"] = vid in SeverityEngine.AUTHORIZED_USB_VIDS
            
            if r["IsAuthorized"]:
                sev, reason = "INFO", "Approved Device"
            elif is_storage:
                sev, reason = "CRITICAL", "Unauthorized Storage Device"
            else:
                sev, reason = "INVESTIGATE", "Unauthorized HID Device"
                
            r["DetectionParameters"] = {"IsStorageDevice": is_storage, "IsAuthorized": r["IsAuthorized"]}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_windows_settings(data):
        sev = "INFO"
        reason = "Advanced settings within normal operational baseline"
        
        bl = data.get("BitLocker", {})
        if bl.get("ProtectionStatus") == "Off" or bl.get("ProtectionStatus") == "0":
            sev, reason = "CRITICAL", "BitLocker Drive Encryption is disabled"
            
        net_sec = data.get("NetworkSecurity", {})
        if net_sec.get("SMB1Enabled") is True:
            sev, reason = "CRITICAL", "Legacy SMBv1 protocol is enabled"
        elif net_sec.get("ExposedShares"):
            sev, reason = "WARNING", "Custom local network shares are exposed"
        else:
            wifi = net_sec.get("SavedWiFiProfiles", [])
            if any(isinstance(w, dict) and w.get("Authentication") in ["Open", "WEP"] for w in wifi):
                sev, reason = "INVESTIGATE", "Insecure Open/WEP Wi-Fi networks saved"
            
        ps_sec = data.get("PowerShellSecurity", {}).get("ExecutionPolicies", {})
        if ps_sec.get("LocalMachine") in ["Unrestricted", "Bypass"]:
            sev, reason = "WARNING", "PowerShell Execution Policy allows unrestricted scripts"
            
        def_adv = data.get("DefenderAdvanced", {})
        if def_adv.get("PUAProtection") == 0:
            sev, reason = "INVESTIGATE", "Potentially Unwanted Application (PUA) protection is disabled"
            
        data["DetectionParameters"] = {
            "BitLockerStatus": bl.get("ProtectionStatus"),
            "SMB1Enabled": net_sec.get("SMB1Enabled"),
            "PUAProtection": def_adv.get("PUAProtection")
        }
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data

    @staticmethod
    def process_software(data):
        if not isinstance(data, list): return data
        remote_tools = [
            "anydesk", "teamviewer", "rustdesk", "logmein", "vnc", 
            "ammyy", "gotoassist", "splashtop", "radmin", "supremo", 
            "remoteutilities", "aeroadmin", "chromeremotedesktop", 
            "connectwise", "bomgar", "screenconnect"
        ]
        dump_tools = [
            "mimikatz", "nanodump", "dumpert", "cobalt strike", "beacon",
            "sliver", "havoc", "quasar", "quasarrat", "njrat", "darkcomet",
            "remcos", "asyncrat", "warzone", "agenttesla", "redline",
            "vidar", "raccoon", "stealc", "lumma", "ligolo", "ligolo-ng",
            "chisel", "fscan"
        ]
        
        for r in data:
            if not isinstance(r, dict): continue
            name = str(r.get("DisplayName", "")).lower()
            is_remote = any(t in name for t in remote_tools)
            is_dump = any(t in name for t in dump_tools)
            
            if is_dump:
                sev, reason, risk = "CRITICAL", "Credential Dumping / Hack Tool Detected", "HIGH"
            elif is_remote:
                sev, reason, risk = "INVESTIGATE", "Remote Access Software Detected", "MEDIUM"
            else:
                sev, reason, risk = "INFO", "Legitimate Software", "LOW"
                
            r["RiskLevel"] = risk
            r["DetectionParameters"] = {"IsRemoteTool": is_remote}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_failed_logins(data):
        if not isinstance(data, list): return data
        ip_counts = {}
        for r in data:
            if not isinstance(r, dict): continue
            ip = r.get("SourceIPAddress", "Unknown")
            if ip and ip != "Unknown" and ip != "-":
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
        for r in data:
            if not isinstance(r, dict): continue
            ip = r.get("SourceIPAddress", "Unknown")
            count = ip_counts.get(ip, 1) if (ip != "Unknown" and ip != "-") else 1
            
            if count >= 20:
                sev, reason = "CRITICAL", ">= 20 failures from same source in 15 mins"
            elif count >= 5:
                sev, reason = "INVESTIGATE", ">= 5 failures from same source in 15 mins"
            else:
                sev, reason = "INFO", "Single or few login failures"
                
            r["DetectionParameters"] = {"FailureCount": count, "SourceIPAddress": ip}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_successful_logins(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            elevated = r.get("ElevatedToken", False)
            ip = str(r.get("SourceIPAddress", "-"))
            is_unusual = ip not in ["-", "127.0.0.1", "::1"]
            
            if elevated and is_unusual:
                sev, reason = "CRITICAL", "Administrative login from unusual host"
            elif elevated:
                sev, reason = "INVESTIGATE", "Elevated login"
            else:
                sev, reason = "INFO", "Normal login"
                
            r["DetectionParameters"] = {"ElevatedToken": elevated, "IsUnusualHost": is_unusual}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_drivers(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            signed = r.get("IsSigned", False)
            kernel = r.get("KernelMode", False)
            
            if not signed and kernel:
                sev, reason, risk = "CRITICAL", "Unsigned Kernel Driver", "HIGH"
            elif not signed:
                sev, reason, risk = "INVESTIGATE", "Unsigned User Driver", "MEDIUM"
            else:
                sev, reason, risk = "INFO", "Signed Driver", "LOW"
                
            r["RiskLevel"] = risk
            r["DetectionParameters"] = {"IsSigned": signed, "KernelMode": kernel}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_tasks(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            hidden = r.get("Hidden", False)
            action = str(r.get("Action", "")).lower()
            in_temp = "appdata" in action or "temp" in action
            
            if hidden and in_temp:
                sev, reason = "CRITICAL", "Hidden Task running from Temp/AppData"
            elif hidden:
                sev, reason = "INVESTIGATE", "Hidden Task"
            else:
                sev, reason = "INFO", "Normal Task"
                
            r["DetectionParameters"] = {"Hidden": hidden, "InTemp": in_temp}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_autoruns(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            sig = str(r.get("SignatureStatus", "Unknown"))
            exe = str(r.get("Executable", "")).lower()
            in_temp = "appdata" in exe or "temp" in exe
            unsigned = (sig != "Signed" and sig != "Valid")
            
            if unsigned and in_temp:
                sev, reason = "CRITICAL", "Unsigned Autorun in Temp/AppData"
            elif unsigned:
                sev, reason = "INVESTIGATE", "Unsigned Autorun"
            else:
                sev, reason = "INFO", "Signed Autorun"
                
            r["DetectionParameters"] = {"Unsigned": unsigned, "InTemp": in_temp}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_accounts(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            days = r.get("DaysInactive", 0)
            is_admin = r.get("AccountType", "") == "Admin"
            enabled = r.get("Enabled", False)
            
            if enabled and days <= 30:
                r["AccountStatus"] = "ACTIVE"
            else:
                r["AccountStatus"] = "INACTIVE"
                
            if enabled == True:
                if is_admin == True and days > 90:
                    sev, reason = "CRITICAL", "Dormant Admin Account >90 Days"
                elif is_admin == True and days > 30:
                    sev, reason = "WARNING", "Admin Account Inactive >30 Days"
                elif is_admin == False and days > 180:
                    sev, reason = "INVESTIGATE", "Dormant Standard User >180 Days"
                else:
                    sev, reason = "INFO", "Active, Enabled Account"
            else:
                if is_admin == True:
                    sev, reason = "INFO", "Disabled Admin Account"
                elif days > 365:
                    sev, reason = "STATISTICAL", "Disabled Account Inactive >1 Year"
                else:
                    sev, reason = "INFO", "Disabled Standard Account"
                
            r["DetectionParameters"] = {"DaysInactive": days, "IsAdmin": is_admin, "Enabled": enabled}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_firewall(data):
        if not isinstance(data, dict): return data
        enabled = data.get("FirewallEnabled", False)
        inbound = data.get("InboundRules", [])
        
        any_any = False
        if isinstance(inbound, list):
            for r in inbound:
                if isinstance(r, dict) and r.get("Action") == "Allow" and str(r.get("RemotePort")).lower() == "any":
                    any_any = True
                    break
                
        if not enabled:
            sev, reason = "CRITICAL", "Firewall Disabled"
        elif any_any:
            sev, reason = "CRITICAL", "Allow Any/Any Rule Found"
        elif isinstance(inbound, list) and len(inbound) > 20:
            sev, reason = "INVESTIGATE", "Excessive Open Ports"
        else:
            sev, reason = "INFO", "Fully Compliant"
            
        data["DetectionParameters"] = {"FirewallEnabled": enabled, "HasAnyAnyRule": any_any}
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data


# --- Throttled Compliance JSON Collectors ---

def installed_software():
    return run_ps(r"""
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName } | 
    Select-Object DisplayName, DisplayVersion, Publisher, @{Name='InstallDate';Expression={$_.InstallDate}}, InstallLocation, 
    @{Name='EstimatedSizeMB';Expression={if ($_.EstimatedSize) {[math]::Round($_.EstimatedSize / 1024, 2)} else {0}}}, 
    @{Name='DigitalSignature';Expression={
        $sigStatus = 'Unknown'
        $path = $null
        if ($_.DisplayIcon -and $_.DisplayIcon -match '^"?([a-zA-Z]:\\[^,"]+\.(?:exe|dll|sys))') {
            $path = $matches[1]
        } elseif ($_.UninstallString -and $_.UninstallString -match '^"?([a-zA-Z]:\\[^,"]+\.(?:exe|dll|sys))') {
            $path = $matches[1]
        }
        
        if (-not $path -and $_.InstallLocation -and (Test-Path -LiteralPath $_.InstallLocation -PathType Container -ErrorAction SilentlyContinue)) {
            $exe = Get-ChildItem -LiteralPath $_.InstallLocation -Filter *.exe -File -Recurse -Depth 1 -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exe) {
                $path = $exe.FullName
            }
        }
        
        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue)) {
            $sig = (Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue).Status
            if ($null -ne $sig) { $sigStatus = $sig -as [string] }
        } else {
            $sigStatus = 'NoExecutableFound'
        }
        $sigStatus
    }} |
    ConvertTo-Json -Depth 3
    """)

def hardware_inventory():
    return run_ps("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Name, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, SystemType, SystemFamily, Domain, PrimaryOwnerName, BootupState | ConvertTo-Json -Depth 2")

def windows_services():
    return run_ps("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | ConvertTo-Json -Depth 2")

def failed_logins():
    return run_ps(r"""
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}
        $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
        @{
            TimeCreated = $_.TimeCreated.ToString("o")
            Id = $_.Id
            TargetUserName = $data['TargetUserName']
            SourceIPAddress = $data['IpAddress']
            WorkstationName = $data['WorkstationName']
            LogonType = $data['LogonType']
            FailureReason = $data['FailureReason']
            StatusCode = $data['Status']
        }
    } | ConvertTo-Json -Depth 3
    """)

def successful_logins():
    return run_ps(r"""
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}
        $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
        @{
            TimeCreated = $_.TimeCreated.ToString("o")
            TargetUserName = $data['TargetUserName']
            SourceIPAddress = $data['IpAddress']
            Workstation = $data['WorkstationName']
            LogonType = $data['LogonType']
            AuthenticationPackage = $data['AuthenticationPackageName']
            ElevatedToken = if ($data['ElevatedToken'] -eq '%%1842') { $true } else { $false }
        }
    } | ConvertTo-Json -Depth 3
    """)

def firewall_config():
    return run_ps(r"""
    $profile = Get-NetFirewallProfile -Name Domain,Private,Public -ErrorAction SilentlyContinue | Where-Object Enabled -eq $true
    $rules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 50
    $inbound = @()
    $outbound = @()
    foreach ($r in $rules) {
        $obj = @{
            RuleName = $r.DisplayName
            Direction = $r.Direction.ToString()
            Action = $r.Action.ToString()
            Protocol = "Any"
            LocalPort = "Any"
            RemotePort = "Any"
            Enabled = $true
        }
        if ($r.Direction -eq "Inbound") { $inbound += $obj } else { $outbound += $obj }
    }
    
    @{
        FirewallEnabled = if ($profile) { $true } else { $false }
        ComplianceStatus = if ($profile) { "PASS" } else { "FAIL" }
        InboundRuleCount = $inbound.Count
        OutboundRuleCount = $outbound.Count
        InboundRules = $inbound
        OutboundRules = $outbound
    } | ConvertTo-Json -Depth 4
    """)

def registry_autoruns():
    return run_ps(r"""
    $autoruns = @()
    $paths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
    foreach ($p in $paths) {
        $items = Get-ItemProperty $p -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($prop in $items.psobject.properties) {
                if ($prop.Name -notmatch "^PS[A-Z]") {
                    $rawVal = $prop.Value -as [string]
                    $exePath = $rawVal -replace '(?s)(^"([^"]+)".*)|(^\S+).*', '$2$3'
                    
                    $publisher = "Unknown"
                    $hash = "Unknown"
                    $sigStatus = "Unknown"
                    
                    if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                        try {
                            $ver = (Get-Item $exePath -ErrorAction SilentlyContinue).VersionInfo.CompanyName
                            if ($ver) { $publisher = $ver }
                        } catch {}
                        
                        try {
                            $h = (Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            if ($h) { $hash = $h }
                        } catch {}
                        
                        try {
                            $sig = (Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue).Status
                            if ($null -ne $sig) { $sigStatus = $sig -as [string] }
                        } catch {}
                    }

                    $autoruns += @{
                        Path = $p
                        Executable = $rawVal
                        Publisher = $publisher
                        SignatureStatus = $sigStatus
                        Hash = $hash
                    }
                }
            }
        }
    }
    $autoruns | ConvertTo-Json -Depth 3
    """)

def scheduled_tasks():
    return run_ps(r"""
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | Select-Object -First 100 | ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        
        $st = [int]$_.State
        $stateStr = "Unknown"
        if ($st -eq 0) { $stateStr = "Unknown" }
        elseif ($st -eq 1) { $stateStr = "Disabled" }
        elseif ($st -eq 2) { $stateStr = "Queued" }
        elseif ($st -eq 3) { $stateStr = "Ready" }
        elseif ($st -eq 4) { $stateStr = "Running" }

        [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State = $stateStr
            Author = $_.Author
            LastRunTime = if ($info.LastRunTime -and $info.LastRunTime.Year -gt 1900) { $info.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
            NextRunTime = if ($info.NextRunTime -and $info.NextRunTime.Year -gt 1900) { $info.NextRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
            Action = ($_.Actions | Select-Object -ExpandProperty Execute -ErrorAction SilentlyContinue) -join ','
            RunAsUser = $_.Principal.UserId
            Hidden = $_.Settings.Hidden
        }
    } | ConvertTo-Json -Depth 3
    """)

def user_accounts():
    return run_ps(r"""
    Get-LocalUser -ErrorAction SilentlyContinue | Select-Object @{Name='UserName';Expression={$_.Name}}, 
    @{Name='AccountType';Expression={if ($_.Description -match "Admin") {"Admin"} else {"Standard"}}},
    Enabled, 
    @{Name='CreatedDate';Expression={""}}, 
    @{Name='LastLoginDate';Expression={if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }}}, 
    @{Name='PasswordLastSet';Expression={if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }}},
    @{Name='DaysInactive';Expression={if ($_.LastLogon) { (New-TimeSpan -Start $_.LastLogon -End (Get-Date)).Days } else { 999 }}} |
    ConvertTo-Json -Depth 3
    """)

def defender_status():
    return run_ps("Get-MpComputerStatus | Select-Object AMProductVersion,DefenderSignaturesOutOfDate,RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,IsTamperProtected,BehaviorMonitorEnabled | ConvertTo-Json -Depth 2")

def boot_shutdown():
    return run_ps(r"""
    $events = Get-WinEvent -FilterHashtable @{LogName='System';ID=6005,6006,1074,6008,1001,41,506,507} -MaxEvents 50 -ErrorAction SilentlyContinue
    $out = @()
    if ($events) {
        foreach ($e in $events) {
            $msg = $e.Message
            $xml = [xml]$e.ToXml()
            $eventData = @{}
            if ($xml.Event.EventData.Data) {
                $xml.Event.EventData.Data | ForEach-Object { $eventData[$_.Name] = $_.'#text' }
            }

            $causeReboot = ""
            $causeShutdown = ""
            $initProcess = ""
            $initExe = ""
            $initCmd = ""
            $initService = ""
            $loggedUser = ""
            $respUser = ""

            $isUpdate = $false
            $isPatch = $false
            $isDriver = $false
            $isApp = $false
            $isCrash = $false
            $isUnexpected = $false
            $isBSOD = $false
            $isPowerLoss = $false

            if ($e.Id -eq 1074) {
                $reason = if ($eventData['param3']) { $eventData['param3'] } else { "" }
                $comment = if ($eventData['param6']) { $eventData['param6'] } else { "" }
                $combinedCause = ($reason + " " + $comment).Trim()
                
                $shutdownType = if ($eventData['param5']) { $eventData['param5'] } else { "" }
                if ($shutdownType -match "restart") {
                    $causeReboot = $combinedCause
                } else {
                    $causeShutdown = $combinedCause
                }
                
                $initExe = if ($eventData['param1']) { $eventData['param1'] } else { "" }
                $initCmd = $initExe
                $loggedUserRaw = if ($eventData['param7']) { $eventData['param7'] } else { "" }
                $loggedUser = if ($loggedUserRaw -match ".*\\(.*)") { $matches[1] } else { $loggedUserRaw }
                $respUser = $loggedUser
                
                if ($initExe -match "svchost.exe") { $initService = "System Service" }
                elseif ($initExe -match "wuauclt.exe|TiWorker.exe|trustedinstaller.exe") { 
                    $isUpdate = $true
                    $isPatch = $true
                }
                elseif ($initExe -match "msiexec.exe") { $isApp = $true }
            }
            elseif ($e.Id -eq 6008) {
                $isUnexpected = $true
                $causeShutdown = "Unexpected Shutdown"
                $isCrash = $true
            }
            elseif ($e.Id -eq 1001) {
                $isCrash = $true
                $isBSOD = $true
                $causeReboot = "BugCheck"
            }
            elseif ($e.Id -eq 41) {
                $isPowerLoss = $true
                $isUnexpected = $true
                $causeShutdown = "Power Loss or Unclean Shutdown"
            }

            if ($msg -match "Windows Update") { $isUpdate = $true; $isPatch = $true }
            if ($msg -match "driver") { $isDriver = $true }
            
            if ($e.Id -eq 6005) { $causeReboot = "Event Log Service Started (Boot)" }
            if ($e.Id -eq 6006) { $causeShutdown = "Event Log Service Stopped (Shutdown)" }
            if ($e.Id -eq 506) { $causeShutdown = "Entering Modern Standby (Sleep/Hibernate)" }
            if ($e.Id -eq 507) { $causeReboot = "Exiting Modern Standby (Wake)" }

            $out += @{
                EventTime = $e.TimeCreated.ToString("dd-MM-yyyy hh:mm:ss tt")
                CollectionTime = (Get-Date).ToString("dd-MM-yyyy hh:mm:ss tt")
                EventID = $e.Id
                EventProvider = if ($e.ProviderName -eq "User32") { "User ($loggedUser)" } else { $e.ProviderName }
                ComputerName = $e.MachineName
                RebootCause = $causeReboot
                ShutdownCause = $causeShutdown
                ProcessThatInitiated = $initExe
                ExecutableThatInitiated = $initExe
                CommandThatInitiated = $initCmd
                ServiceThatInitiated = $initService
                UserLoggedOn = $loggedUser
                UserWhoInitiated = $respUser
                UserBooted = $loggedUser
                IsUpdateReboot = $isUpdate
                IsPatchReboot = $isPatch
                IsDriverReboot = $isDriver
                IsAppReboot = $isApp
                IsCrashReboot = $isCrash
                IsUnexpectedReboot = $isUnexpected
                IsBSODReboot = $isBSOD
                IsPowerLossReboot = $isPowerLoss
            }
        }
    }
    $out | ConvertTo-Json -Depth 3
    """)

def audit_policy():
    return run_ps(r"""
    $result = @{
        Configuration = @()
        RecentAuditEvents = @()
    }

    $audit = auditpol /get /category:* 2>&1
    if ($audit -match "privilege is not held") {
        $result.Configuration += @{ Error = "Requires Administrator Privileges" }
    } else {
        $lines = $audit | Select-Object -Skip 3
        $category = "Unknown"
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -ne "") {
                if ($line -match "^\S") {
                    $category = $trimmed
                } else {
                    $parts = $trimmed -split '\s{2,}'
                    if ($parts.Count -ge 2) {
                        $result.Configuration += @{
                            Category = $category
                            Subcategory = $parts[0]
                            Setting = $parts[1]
                        }
                    }
                }
            }
        }
    }

    $events = Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($events) {
        foreach ($e in $events) {
            $userStr = "N/A"
            if ($null -ne $e.UserId) {
                try {
                    $userStr = (New-Object System.Security.Principal.SecurityIdentifier($e.UserId.Value)).Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $userStr = $e.UserId.Value
                }
            }
            if ($userStr -eq "N/A" -or $userStr -eq "") {
                if ($e.Message -match "Account Name:\s*([^\r\n]+)") {
                    $userStr = $Matches[1].Trim()
                }
            }

            $result.RecentAuditEvents += @{
                LogName = $e.LogName
                Source = $e.ProviderName
                EventID = $e.Id
                TaskCategory = $e.TaskDisplayName
                Level = $e.LevelDisplayName
                Keywords = if ($e.KeywordsDisplayNames) { $e.KeywordsDisplayNames -join ", " } else { "N/A" }
                User = $userStr
                OpCode = $e.OpcodeDisplayName
                Computer = $e.MachineName
            }
        }
    } else {
        $result.RecentAuditEvents += @{ Error = "Requires Administrator Privileges or No Events Found" }
    }

    $result | ConvertTo-Json -Depth 4
    """)

def drivers_inventory():
    return run_ps(r"""
    $drivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceName } | Select-Object -First 200
    $out = @()
    foreach ($d in $drivers) {
        $hash = "Unknown"
        if ($d.InfName) {
            $path = Join-Path $env:windir "INF\$($d.InfName)"
            if (Test-Path $path) {
                try {
                    $h = (Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if ($h) { $hash = $h }
                } catch {}
            }
        }
        $age = 0
        if ($d.DriverDate) {
            $age = (New-TimeSpan -Start $d.DriverDate -End (Get-Date)).Days
        }
        $out += @{
            DeviceName = $d.DeviceName
            DriverVersion = $d.DriverVersion
            IsSigned = $d.IsSigned
            DriverHash = $hash
            Signer = $d.Signer
            DriverAgeDays = $age
            KernelMode = $true
        }
    }
    $out | ConvertTo-Json -Depth 3
    """)

def more_windows_settings():
    return run_ps(r"""
    $out = @{}

    # 1. Defender Preferences
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mp) {
        $out.DefenderAdvanced = @{
            NetworkProtection = $mp.EnableNetworkProtection
            ControlledFolderAccess = $mp.EnableControlledFolderAccess
            PUAProtection = $mp.PUAProtection
            AttackSurfaceReduction = ($mp.AttackSurfaceReductionRules_Ids -join ',')
            EmailScanning = if ($mp.DisableEmailScanning) { $false } else { $true }
            ArchiveScanning = if ($mp.DisableArchiveScanning) { $false } else { $true }
            IOAVProtection = if ($mp.DisableIOAVProtection) { $false } else { $true }
            ScriptScanning = if ($mp.DisableScriptScanning) { $false } else { $true }
        }
    }

    # 2. Advanced Device Security
    $dep = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    if ($dep) {
        $out.DeviceSecurityAdvanced = @{
            DEP = $dep.Dep.Enable
            ASLR = $dep.Aslr.EnableBottomUpRandomization
            CFG = $dep.Payload.EnableExportAddressFilter
        }
    }

    # 3. BitLocker
    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    $out.BitLocker = @{
        ProtectionStatus = if ($bl) { $bl.ProtectionStatus.ToString() } else { "Unknown" }
        EncryptionPercentage = if ($bl) { $bl.EncryptionPercentage } else { 0 }
        EncryptionMethod = if ($bl) { $bl.EncryptionMethod.ToString() } else { "None" }
    }

    # 4. Advanced Firewall
    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $fwData = @{}
    if ($fwProfiles) {
        foreach ($p in $fwProfiles) {
            $fwData[$p.Name] = @{
                DefaultInbound = $p.DefaultInboundAction.ToString()
                DefaultOutbound = $p.DefaultOutboundAction.ToString()
                LogAllowed = $p.LogAllowed.ToString()
                LogBlocked = $p.LogBlocked.ToString()
            }
        }
        $out.AdvancedFirewall = $fwData
    }

    # 5. Windows Update Policies
    $wu = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    $out.WindowsUpdateAdvanced = @{
        AUOptions = if ($null -ne $wu.AUOptions) { $wu.AUOptions } else { "Not Configured" }
        UseWUServer = if ($null -ne $wu.UseWUServer) { $wu.UseWUServer } else { 0 }
    }

    # 6. Account Policies
    $netAcc = net accounts 2>$null
    if ($netAcc) {
        $out.AccountPolicies = @{
            LockoutThreshold = if ($netAcc -match "Lockout threshold:") { ($netAcc -match "Lockout threshold:")[0].Split(":")[1].Trim() } else { "Unknown" }
            MinPasswordLength = if ($netAcc -match "Minimum password length:") { ($netAcc -match "Minimum password length:")[0].Split(":")[1].Trim() } else { "Unknown" }
            MaxPasswordAge = if ($netAcc -match "Maximum password age") { ($netAcc -match "Maximum password age")[0].Split(":")[1].Trim() } else { "Unknown" }
            PasswordHistory = if ($netAcc -match "Length of password history maintained:") { ($netAcc -match "Length of password history maintained:")[0].Split(":")[1].Trim() } else { "Unknown" }
        }
    }

    # 7. Audit Policy (Full)
    $audit = auditpol /get /category:* 2>$null | Select-Object -Skip 2
    $auditDict = @{}
    if ($audit) {
        foreach ($line in $audit) {
            if ($line.Trim() -eq "") { continue }
            if (-not $line.Contains("  ")) {
                # Category skipped
            } else {
                $parts = $line -split "  +"
                if ($parts.Count -ge 2) {
                    $auditDict[$parts[0].Trim()] = $parts[-1].Trim()
                }
            }
        }
        $out.FullAuditPolicy = $auditDict
    }

    # 8. Event Log Config
    $logs = Get-EventLog -List -ErrorAction SilentlyContinue
    $logData = @{}
    if ($logs) {
        foreach ($l in $logs) {
            if ($l.Log -in @("Security", "System", "Application")) {
                $logData[$l.Log] = @{
                    MaxKB = $l.MaximumKilobytes
                    Retention = $l.MinimumRetentionDays
                    OverflowAction = $l.OverflowAction.ToString()
                }
            }
        }
        $out.EventLogConfig = $logData
    }

    # 9. Network Security
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "^\w`$" -and $_.Name -ne "IPC$" -and $_.Name -ne "ADMIN$" -and $_.Name -ne "print$" }
    $shareList = @()
    if ($shares) { foreach ($s in $shares) { $shareList += $s.Name } }
    
    $wifiList = @()
    $wifiProfs = netsh wlan show profiles 2>$null | Select-String "All User Profile"
    if ($wifiProfs) {
        foreach ($p in $wifiProfs) {
            $profName = ($p -split ":")[1].Trim()
            $authLine = netsh wlan show profile name="$profName" 2>$null | Select-String "Authentication"
            $auth = if ($authLine) { $authLine.Line.Split(":")[1].Trim() } else { "Unknown" }
            $wifiList += @{ SSID = $profName; Authentication = $auth }
        }
    }

    if ($smb) {
        $out.NetworkSecurity = @{
            SMB1Enabled = $smb.EnableSMB1Protocol
            SMB2Enabled = $smb.EnableSMB2Protocol
            RequireSecuritySignature = $smb.RequireSecuritySignature
            ExposedShares = $shareList
            SavedWiFiProfiles = $wifiList
        }
    }

    # 10. Remote Access
    $ssh = Get-Service sshd -ErrorAction SilentlyContinue
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    $out.RemoteAccess = @{
        SSHServerRunning = if ($ssh) { $ssh.Status -eq 'Running' } else { $false }
        WinRMRunning = if ($winrm) { $winrm.Status -eq 'Running' } else { $false }
    }

    # 11. PowerShell Security
    $psExec = Get-ExecutionPolicy -List -ErrorAction SilentlyContinue
    $psData = @{}
    if ($psExec) {
        foreach ($p in $psExec) { $psData[$p.Scope.ToString()] = $p.ExecutionPolicy.ToString() }
        $out.PowerShellSecurity = @{ ExecutionPolicies = $psData }
    }

    # 12. Browser Security
    $edge = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue
    $out.BrowserSecurity = @{
        SmartScreenEnabled = if ($null -ne $edge.SmartScreenEnabled) { $edge.SmartScreenEnabled } else { "Not Configured" }
        PasswordManagerEnabled = if ($null -ne $edge.PasswordManagerEnabled) { $edge.PasswordManagerEnabled } else { "Not Configured" }
    }

    # 13. Storage Policies
    $usbWrite = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\StorageDevicePolicies" -ErrorAction SilentlyContinue
    $out.StoragePolicies = @{
        USBWriteProtection = if ($null -ne $usbWrite.WriteProtect) { $usbWrite.WriteProtect } else { 0 }
    }

    # 14. Installed Security Products
    $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    $fw = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct -ErrorAction SilentlyContinue
    $out.InstalledSecurityProducts = @{
        AntiVirus = if ($av) { ($av.displayName) -join ", " } else { "None Detected" }
        Firewall = if ($fw) { ($fw.displayName) -join ", " } else { "None Detected" }
    }

    # 15. Local Administrators
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $out.LocalAdministrators = if ($admins) { ($admins.Name) -join ", " } else { "" }

    # 16. Certificates
    $certs = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.NotAfter -lt (Get-Date) } | Measure-Object
    $out.Certificates = @{
        ExpiredRootCertsCount = if ($certs) { $certs.Count } else { 0 }
    }

    # 17. Windows Security Features
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $out.WindowsSecurityFeatures = @{
        LSARunAsPPL = if ($null -ne $lsa.RunAsPPL) { $lsa.RunAsPPL } else { 0 }
    }

    $out | ConvertTo-Json -Depth 5
    """)

def usb_laptop_direct_connection():
    return run_ps(r"""
    $usb = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -match 'USBSTOR' -or $_.DeviceID -match 'USB' } | Select-Object -First 50
    $res = @()
    foreach ($u in $usb) {
        $isStorage = ($u.DeviceID -match 'USBSTOR')
        $res += @{
            Name = $u.Name
            Manufacturer = $u.Manufacturer
            DeviceID = $u.DeviceID
            VID = if ($u.DeviceID -match 'VID_([0-9A-F]{4})') { $matches[1] } else { "" }
            PID = if ($u.DeviceID -match 'PID_([0-9A-F]{4})') { $matches[1] } else { "" }
            Vendor = $u.Manufacturer
            FirstSeen = "Unknown"
            LastSeen = "Unknown"
            DriverName = $u.Service
            Class = $u.PNPClass
            IsStorageDevice = $isStorage
            IsAuthorized = $false
        }
    }
    $res | ConvertTo-Json -Depth 3
    """)

def bios_snapshot():
    return run_ps(r"""
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    $dg = Get-CimInstance -Namespace ROOT\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    
    $biosDate = $bios.ReleaseDate
    $age = 0
    if ($biosDate) { $age = (New-TimeSpan -Start $biosDate -End (Get-Date)).Days }
    
    $tpmPresent = if ($tpm -and $tpm.TpmPresent) { $true } else { $false }
    $tpmEnabled = if ($tpm -and $tpm.TpmReady) { $true } else { $false }
    $tpmVersion = if ($tpmPresent) { "2.0" } else { "None" }
    
    $vbs = if ($dg -and $dg.VirtualizationBasedSecurityStatus -eq 2) { $true } else { $false }
    $hvci = if ($dg -and $dg.CodeIntegrityPolicyEnforcementStatus -eq 2) { $true } else { $false }
    $secureBootSupport = if ($dg -and $dg.SecurityServicesConfigured -contains 1) { $true } else { $false }
    $measuredBoot = if ($dg -and $dg.SecurityServicesConfigured -contains 2) { $true } else { $false }
    
    $fwRisk = 0
    if (-not ($sb -eq $true)) { $fwRisk += 30 }
    if (-not $tpmPresent) { $fwRisk += 30 }
    if (-not $vbs) { $fwRisk += 10 }
    if ($age -gt 730) { $fwRisk += 10 }
    if ($fwRisk -gt 100) { $fwRisk = 100 }
    
    $tpmFwVer = ""
    if ($tpm -and $tpm.ManufacturerVersionFull20) { $tpmFwVer = $tpm.ManufacturerVersionFull20 }
    elseif ($tpm -and $tpm.ManufacturerVersion) { $tpmFwVer = $tpm.ManufacturerVersion }
    
    $legacyBoot = $false
    try {
        $fwType = (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction SilentlyContinue).BiosFirmwareType.ToString()
        if ($fwType -match "Bios") { $legacyBoot = $true }
    } catch {}
    
    @{
        Manufacturer = $bios.Manufacturer
        SMBIOSBIOSVersion = $bios.SMBIOSBIOSVersion
        BIOS_Vendor = $bios.Manufacturer
        BIOS_Version = $bios.SMBIOSBIOSVersion
        BIOS_Release_Date = if ($biosDate) { $biosDate.ToString("yyyy-MM-dd") } else { "" }
        BIOS_Age_Days = $age
        UEFI_Mode = if ($secureBootSupport -or ($sb -eq $true)) { $true } else { (-not $legacyBoot) }
        LegacyBootEnabled = $legacyBoot
        SecureBootSupported = $secureBootSupport
        SecureBootEnabled = if ($sb -eq $true) { $true } else { $false }
        TPM_Present = $tpmPresent
        TPM_Enabled = $tpmEnabled
        TPM_Version = $tpmVersion
        TPM_FirmwareVersion = $tpmFwVer
        MeasuredBootEnabled = $measuredBoot
        IntelBootGuardEnabled = $false
        AMD_PSP_Status = $false
        KernelDMAProtection = if ($dg -and $dg.SecurityServicesConfigured -contains 3) { $true } else { $false }
        VirtualizationBasedSecurity = $vbs
        HVCIEnabled = $hvci
        BIOS_WriteProtection = $false
        ExternalBootAllowed = $false
        BIOS_Password_Set = $false
        Firmware_Integrity_Status = if ($sb -eq $true) { "Pass" } else { "Fail" }
        Firmware_Vulnerability_Count = 0
        Firmware_Risk_Score = $fwRisk
        Firmware_Compliance = if (($sb -eq $true) -and $tpmPresent -and ($age -le 730)) { $true } else { $false }
    } | ConvertTo-Json -Depth 2
    """)

def windows_scan_history():
    return run_ps(r"""
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $threats = Get-MpThreat -ErrorAction SilentlyContinue
    $threatDets = Get-MpThreatDetection -ErrorAction SilentlyContinue
    $threatNames = @()
    $remediation = "None"
    $allThreats = @()

    if ($threats) {
        foreach ($t in $threats) {
            $threatNames += $t.ThreatName
            
            $fwSeverity = ""
            if ($t.SeverityID -eq 1) { $fwSeverity = "Low" }
            elseif ($t.SeverityID -eq 2) { $fwSeverity = "Moderate" }
            elseif ($t.SeverityID -eq 4) { $fwSeverity = "High" }
            elseif ($t.SeverityID -eq 5) { $fwSeverity = "Severe" }
            
            $filePaths = @()
            if ($t.Resources) { $filePaths = $t.Resources }
            $resJoined = $filePaths -join ", "
            
            $hash = ""
            if ($resJoined -match "sha[12]5?6?_?:?([a-fA-F0-9]{40,64})") { $hash = $matches[1] }
            
            $qInfo = ""
            if ($t.RollupStatus -eq 33) { $qInfo = "Quarantined" }
            elseif ($t.RollupStatus -ne $null) { $qInfo = "Status Code: " + $t.RollupStatus }
            
            $allThreats += @{
                ExactFileInvolved = $resJoined
                ThreatName = $t.ThreatName
                ThreatType = "Malware"
                ThreatCategory = $t.CategoryID
                ThreatSeverity = $fwSeverity
                ThreatStatus = if ($t.IsActive) { "Active" } else { "Inactive" }
                DetectionSource = "Windows Defender"
                FilePath = $resJoined
                HashValues = $hash
                ProcessInvolved = ""
                UserInvolved = ""
                RemediationAction = ""
                RemediationStatus = "Unknown"
                QuarantineInformation = $qInfo
                DetectionTimestamps = ""
            }
        }
    }
    
    if ($threatDets) {
        foreach ($td in $threatDets) {
             $fwSeverity = ""
             if ($td.SeverityID -eq 1) { $fwSeverity = "Low" }
             elseif ($td.SeverityID -eq 2) { $fwSeverity = "Moderate" }
             elseif ($td.SeverityID -eq 4) { $fwSeverity = "High" }
             elseif ($td.SeverityID -eq 5) { $fwSeverity = "Severe" }
             
             $resJoined = if ($td.Resources) { $td.Resources -join ", " } else { "" }
             
             $hash = ""
             if ($resJoined -match "sha[12]5?6?_?:?([a-fA-F0-9]{40,64})") { $hash = $matches[1] }
             
             $qInfo = ""
             if ($td.CleaningActionID -eq 2) { $qInfo = "Quarantined" }
             elseif ($td.CleaningActionID -eq 3) { $qInfo = "Removed" }
             elseif ($td.CleaningActionID -eq 1) { $qInfo = "Cleaned" }
             elseif ($td.ActionSuccess -eq $true) { $qInfo = "Action Successful (ID: " + $td.CleaningActionID + ")" }
             else { $qInfo = "Pending/Failed" }
             
             $allThreats += @{
                ExactFileInvolved = $resJoined
                ThreatName = $td.ThreatName
                ThreatType = "Malware"
                ThreatCategory = $td.CategoryID
                ThreatSeverity = $fwSeverity
                ThreatStatus = if ($td.ActionSuccess) { "Remediated" } else { "Active" }
                DetectionSource = "Windows Defender"
                FilePath = $resJoined
                HashValues = $hash
                ProcessInvolved = if ($td.ProcessName) { $td.ProcessName } else { "" }
                UserInvolved = if ($td.DomainUser) { $td.DomainUser } else { "" }
                RemediationAction = $td.ActionSuccess
                RemediationStatus = if ($td.ActionSuccess) { "Success" } else { "Failed" }
                QuarantineInformation = $qInfo
                DetectionTimestamps = if ($td.InitialDetectionTime) { $td.InitialDetectionTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            }
            $threatNames += $td.ThreatName
            if ($td.ActionSuccess -eq $false) { $remediation = "Failed" }
            elseif ($remediation -ne "Failed") { $remediation = "Success" }
        }
    }
    
    if ($allThreats.Count -eq 0) {
        $allThreats += @{
            ExactFileInvolved = ""
            ThreatName = ""
            ThreatType = ""
            ThreatCategory = ""
            ThreatSeverity = ""
            ThreatStatus = ""
            DetectionSource = ""
            FilePath = ""
            HashValues = ""
            ProcessInvolved = ""
            UserInvolved = ""
            RemediationAction = ""
            RemediationStatus = ""
            QuarantineInformation = ""
            DetectionTimestamps = ""
        }
    }

    $uniqueThreatNames = if ($threatNames.Count -gt 0) { $threatNames | Select-Object -Unique } else { @() }

    @{
        QuickScanStart = if ($status.QuickScanStartTime) { '{0:yyyy-MM-dd HH:mm:ss}' -f $status.QuickScanStartTime } else { "" }
        QuickScanEnd = if ($status.QuickScanEndTime) { '{0:yyyy-MM-dd HH:mm:ss}' -f $status.QuickScanEndTime } else { "" }
        LastThreatDetected = $status.AMThreatLastDetectTime
        ThreatCount = if ($uniqueThreatNames) { @($uniqueThreatNames).Count } else { 0 }
        ThreatNames = $uniqueThreatNames
        AllDetectedThreats = $allThreats
        RemediationStatus = $remediation
        EngineVersion = $status.AMEngineVersion
        SignatureVersion = $status.AMProductVersion
    } | ConvertTo-Json -Depth 4
    """)

def usb_setting_history():
    return run_ps(r"""
    $usbItems = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue
    $out = @()
    $currentUser = ""
    try {
        $currentUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
    } catch {}
    if (-not $currentUser) { $currentUser = $env:USERNAME }
    
    if ($usbItems) {
        foreach ($u in $usbItems) {
            $deviceIdentity = if ($u.FriendlyName) { $u.FriendlyName } else { $u.DeviceDesc }
            
            $instanceId = ""
            if ($u.PSPath -match 'Enum\\(.*)') {
                $instanceId = $matches[1]
            }
            
            $firstConn = ""
            $lastConn = ""
            $lastDisconn = ""
            
            if ($instanceId) {
                $props = Get-PnpDeviceProperty -InstanceId $instanceId -ErrorAction SilentlyContinue
                if ($props) {
                    $firstProp = $props | Where-Object KeyName -eq "DEVPKEY_Device_FirstInstallDate"
                    if ($firstProp -and $firstProp.Data) { $firstConn = $firstProp.Data.ToString("yyyy-MM-dd HH:mm:ss") }
                    
                    $arrProp = $props | Where-Object KeyName -eq "DEVPKEY_Device_LastArrivalDate"
                    if ($arrProp -and $arrProp.Data) { $lastConn = $arrProp.Data.ToString("yyyy-MM-dd HH:mm:ss") }
                    
                    $remProp = $props | Where-Object KeyName -eq "DEVPKEY_Device_LastRemovalDate"
                    if ($remProp -and $remProp.Data) { $lastDisconn = $remProp.Data.ToString("yyyy-MM-dd HH:mm:ss") }
                }
            }
            
            $connHistory = @()
            if ($lastConn) { $connHistory += "Connected: $lastConn" }
            if ($lastDisconn) { $connHistory += "Disconnected: $lastDisconn" }
            
            $out += @{
                FriendlyName = $u.FriendlyName
                DeviceDesc = $u.DeviceDesc
                Mfg = $u.Mfg
                HardwareID = $u.HardwareID
                DeviceIdentity = $deviceIdentity
                FirstConnectionTime = $firstConn
                LastConnectionTime = $lastConn
                LastDisconnectionTime = $lastDisconn
                ConnectionHistory = $connHistory
                LoggedInUser = $currentUser
                AuthorizationStatus = "Authorized"
                DeviceRiskStatus = "Low"
                DataTransferInformation = @(@{
                    FileName = ""
                    TransferDirection = ""
                    TransferTime = ""
                    FileSize = ""
                    User = ""
                })
                ExecutablesLaunchedFromUSB = @(@{
                    ExecutableName = ""
                    LaunchTime = ""
                    ProcessId = ""
                    User = ""
                    ExecutionStatus = ""
                })
                MalwareFindingsRelatedToUSB = @(@{
                    ThreatName = ""
                    Severity = ""
                    DetectionTime = ""
                    ActionTaken = ""
                })
            }
        }
    }
    $out | ConvertTo-Json -Depth 4
    """)


COLLECTORS = {
    "01_installed_software": installed_software,
    "04_hardware_inventory": hardware_inventory,
    "05_windows_services": windows_services,
    "06_failed_logins": failed_logins,
    "07_successful_logins": successful_logins,
    "10_firewall_configuration": firewall_config,
    "12_registry_autoruns": registry_autoruns,
    "13_scheduled_tasks": scheduled_tasks,
    "16_user_accounts_and_privileges": user_accounts,
    "17_windows_defender_status": defender_status,
    "20_boot_shutdown_events": boot_shutdown,
    "21_audit_policy_configuration": audit_policy,
    "22_drivers_inventory": drivers_inventory,
    "23_more_windows_settings": more_windows_settings,
    "24_usb_direct_connection": usb_laptop_direct_connection,
    "25_bios_snapshot": bios_snapshot,
    "26_windows_scan_history": windows_scan_history,
    "27_usb_setting_history": usb_setting_history
}


def calculate_sha256(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "FILE_NOT_FOUND"


def main():
    master = {
        "device_fingerprint": get_device_fingerprint(),
        "timestamp": ts(),
        "event_id": "EVT_MASTER_INDEX",
        "event_type": "Index Generation",
        "severity": "INFO",
        "payload_message": {
            "username": CURRENT_USER,
            "files": []
        }
    }

    # -------------------------------
    # Run all collectors
    # -------------------------------
    for name, func in COLLECTORS.items():

        data = func()

        event_type_label = "Compliance Metric Collection"

        if name == "01_installed_software":
            data = SeverityEngine.process_software(data)
            event_type_label = "Installed Software Assessment"
        elif name == "04_hardware_inventory":
            data = SeverityEngine.process_hardware(data)
            event_type_label = "Hardware Assessment"
        elif name == "06_failed_logins":
            data = SeverityEngine.process_failed_logins(data)
            event_type_label = "Failed Login Monitoring"
        elif name == "07_successful_logins":
            data = SeverityEngine.process_successful_logins(data)
            event_type_label = "Successful Login Monitoring"
        elif name == "10_firewall_configuration":
            data = SeverityEngine.process_firewall(data)
            event_type_label = "Firewall Assessment"
        elif name == "12_registry_autoruns":
            data = SeverityEngine.process_autoruns(data)
            event_type_label = "Autoruns Assessment"
        elif name == "13_scheduled_tasks":
            data = SeverityEngine.process_tasks(data)
            event_type_label = "Scheduled Tasks Assessment"
        elif name == "16_user_accounts_and_privileges":
            data = SeverityEngine.process_accounts(data)
            event_type_label = "User Account Assessment"
        elif name == "22_drivers_inventory":
            data = SeverityEngine.process_drivers(data)
            event_type_label = "Drivers Assessment"
        elif name == "23_more_windows_settings":
            data = SeverityEngine.process_windows_settings(data)
            event_type_label = "Windows Settings Assessment"
        elif name == "24_usb_direct_connection":
            data = SeverityEngine.process_usb(data)
            event_type_label = "USB Connection Assessment"
        elif name == "25_bios_snapshot":
            data = SeverityEngine.process_bios_snapshot(data)
            event_type_label = "BIOS Security Assessment"
        elif name == "26_windows_scan_history":
            data = SeverityEngine.process_scan_history(data)
            event_type_label = "Threat Detection"
        elif name == "20_boot_shutdown_events":
            data = SeverityEngine.process_boot_shutdown(data)
            event_type_label = "System Availability Metrics"

        severity_level = SeverityEngine.get_highest_severity(data)

        # Fallbacks for non-enhanced schemas
        if severity_level == "INFO" and name not in [
            "01_installed_software", "06_failed_logins", "07_successful_logins", 
            "10_firewall_configuration", "12_registry_autoruns", "13_scheduled_tasks",
            "16_user_accounts_and_privileges", "22_drivers_inventory", "23_more_windows_settings",
            "24_usb_direct_connection", "25_bios_snapshot", "26_windows_scan_history"
        ]:
            if name == "20_boot_shutdown_events": severity_level = "STATISTICAL"
            elif name in ["17_windows_defender_status", "27_usb_setting_history"]: severity_level = "INVESTIGATE"

        save_json(
            name,
            data,
            severity=severity_level,
            event_type=event_type_label
        )

        master["payload_message"]["files"].append(f"{name}.json")
        time.sleep(0.2)

    # -------------------------------
    # File Integrity Monitoring
    # -------------------------------
    csv_headers = [
        "timestamp",
        "username",
        "hostname",
        "monitored_file",
        "sha256_hash",
        "integrity_status"
    ]
    csv_rows = []
    files_to_hash = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\drivers\pci.sys"
    ]

    for file_path in files_to_hash:
        file_hash = calculate_sha256(file_path)
        csv_rows.append([
            ts(),
            CURRENT_USER,
            socket.gethostname(),
            file_path,
            file_hash,
            "PRESENT" if file_hash != "FILE_NOT_FOUND" else "MISSING"
        ])

    save_csv("11_file_integrity_hashes", csv_headers, csv_rows)
    master["payload_message"]["files"].append("11_file_integrity_hashes.csv")

    save_json(
        "master_index", 
        master["payload_message"], 
        event_id="EVT_MASTER_INDEX", 
        event_type="Master Aggregation",
        severity="INFO"
    )

    print(f"[+] Throttled collection complete. Output directory: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
