# -Compliance-and-Configuration
Compliance & Configuration Module
Overview

The Compliance & Configuration Module is a component of the Security Operations Center (SOC) pipeline responsible for collecting, analyzing, and reporting Windows system compliance data.

The module performs compliance assessment across multiple system areas, including software inventory, hardware inventory, user accounts, login activity, Windows services, security configurations, USB activity, audit policies, and Windows Defender status.

Collected data is processed through a rules engine and score engine to generate compliance scores and security findings.
Data Points:-


Features

Compliance Checks
Installed Software Inventory
Hardware Inventory
Windows Services Status
Failed Login Analysis
Successful Login Analysis
Firewall Configuration
Registry Autoruns
Scheduled Tasks
User Accounts & Privileges
Windows Defender Status
Boot & Shutdown Events
Audit Policy Configuration
Drivers Inventory
Additional Windows Security Settings
USB Direct Connection Detection
BIOS Snapshot Collection
Windows Scan History
USB Settings History



<h3>Processing Components<h3>

Compliance Data Collector
Rules Engine
Compliance Score Engine
Report Generator
Kafka Integration
Dashboard Integration


<img width="817" height="604" alt="image" src="https://github.com/user-attachments/assets/8e666894-a5bd-4e71-864c-b6619fa54438" />


<h3>Project Structure<h3>
<img width="888" height="573" alt="image" src="https://github.com/user-attachments/assets/ab049815-9693-403a-9c02-fa4c401e5e05" />

<h3>Sample log file:-<h3>
  
{

  "timestamp": "2025-06-14T10:16:28Z",
  
  "level": "INFO",
  
  "module": "report",
  
  "action": "generate_report",
  
  "status": "SUCCESS",
  
  "report_name": "final_report_2025-06-14_101628.json",
  
  "execution_time_ms": 1240
  
}
<img width="691" height="413" alt="image" src="https://github.com/user-attachments/assets/c5fe76c2-b49b-4aa6-8f3a-5998c3be8acd" />


<h3>Execution<h3>

Start Kafka

kafka-server-start.bat config\server.properties

Run Compliance Collection

run_compliance.bat

Verify Topic

kafka-topics.bat --bootstrap-server localhost:9092 --list

<h3>Output<h3>
The module generates:

Compliance Assessment Results

Compliance Scores

Dashboard JSON Data

Security Findings

Compliance Reports
<img width="1600" height="694" alt="WhatsApp Image 2026-06-14 at 23 31 11" src="https://github.com/user-attachments/assets/8a197df9-ff2f-40e5-9b7c-249fc8347342" />

<img width="1642" height="721" alt="image" src="https://github.com/user-attachments/assets/fb214073-53f2-44cf-9386-9a20e262c080" />


