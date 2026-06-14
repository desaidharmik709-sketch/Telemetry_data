# -Compliance-and-Configuration
Compliance & Configuration Module
Overview

The Compliance & Configuration Module is a component of the Security Operations Center (SOC) pipeline responsible for collecting, analyzing, and reporting Windows system compliance data.

The module performs compliance assessment across multiple system areas, including software inventory, hardware inventory, user accounts, login activity, Windows services, security configurations, USB activity, audit policies, and Windows Defender status.

Collected data is processed through a rules engine and score engine to generate compliance scores and security findings.

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

Execution
Start Kafka
kafka-server-start.bat config\server.properties
Run Compliance Collection
run_compliance.bat
Verify Topic
kafka-topics.bat --bootstrap-server localhost:9092 --list
Output

The module generates:

Compliance Assessment Results
Compliance Scores
Dashboard JSON Data
Security Findings
Compliance Reports
<img width="1801" height="856" alt="image" src="https://github.com/user-attachments/assets/69166faf-9c46-4fc3-902a-68c9b69d7e4b" />
<img width="1201" height="720" alt="image" src="https://github.com/user-attachments/assets/040ba0d2-23fc-462f-add0-00436da448e5" />



