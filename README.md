# SOC-Environment-Set-Up
Simulated Security Operation Center (SOC) Environment Lab

This project focuses on building a multi-VM SOC environment for security monitoring, log analysis, and incident response practice. The lab integrates ELK Stack, Splunk, Sysmon, Winlogbeat/Filebeat, and Suricata to simulate real-world Blue Team operations.

Lab Architecture:

SOC Server (Ubuntu Server) running Elasticsearch, Logstash, and Kibana for centralized log collection.

Windows 10 endpoint configured with Sysmon, Winlogbeat, and Splunk Universal Forwarder.

Ubuntu endpoint running Suricata IDS and Filebeat.

Kali Linux used for attack simulation, scanning, and adversarial testing.

Implemented Features:

ELK Stack

Centralized log ingestion through Logstash pipelines

Visualization of Windows Event Logs, Sysmon events, and Suricata alerts in Kibana

Windows Endpoint Monitoring

Sysmon logging process creation, network connections, registry modifications

Winlogbeat forwarding logs to Logstash

Splunk Integration

Splunk Enterprise configured for parallel log analysis

Splunk Universal Forwarder collecting Windows and Linux logs

Custom searches and dashboard creation

Suricata IDS

Network anomaly detection and alerting

EVE JSON logs forwarded to ELK and Splunk

Incident Response Simulation

Malware execution

Persistence techniques

Brute-force attempts

Command and Control (C2) traffic

Log-based detection and analysis workflow

In Progress:

Integration of Wazuh Manager and agents for extended detection and response

Deployment of TheHive and Cortex for case management and automated enrichment

Additional attack scenarios mapped to MITRE ATT&CK techniques

Learning Outcomes:

SIEM configuration and correlation (ELK, Splunk)

Endpoint and network telemetry analysis

IDS alert interpretation and network forensics

Log pipeline design and troubleshooting

Blue Team workflows and incident handling fundamentals

Author:
Le Minh Quan
