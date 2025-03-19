Intrusion Detection System (IDS)

Overview

This project is a Python-based Intrusion Detection System (IDS) designed to detect various network attacks and suspicious activities using Scapy. The IDS identifies threats by analyzing network traffic and implementing detection rules for specific attack patterns.

Features

Real-time Packet Analysis: Monitors network traffic in real-time.

Custom Detection Rules: Implements detection rules for different attack types.

Alert System: Generates alerts when malicious activities are detected.

Extensible: Easily add new detection rules.

User-friendly GUI (Planned): A PyQt/Tkinter-based interface for better usability.

Detection Capabilities

The IDS currently detects:

SMTP Spoofing

HTTP Response Splitting

Planned and under development:

TCP Spoofing Detection

Cross-Site Request Forgery (CSRF) Detection

LDAP Enumeration Detection

Telnet Brute Force Detection

Rogue DHCP Server Detection

NTP Amplification Attack Detection

SMB Null Session Detection

SSH Brute Force Detection

TLS/SSL Certificate Anomaly Detection

Excessive ICMP Request Detection

SMTP Relay Attack Detection

DNS Flood Attack Detection

UDP Flood Attack Detection

Fragmentation Attack Detection

Malicious Web Shell Detection

Exploits for CVEs

Web Application Firewall (WAF) Bypass Detection

Session Fixation Detection

Command Injection Detection

Malware C&C Communication Detection

VPN Protocol Detection

Installation

Prerequisites

Python 3.x

Scapy (pip install scapy)

Other dependencies as needed (requirements.txt to be provided)

Setup

Clone the repository:

git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name

Install dependencies:

pip install -r requirements.txt

Run the IDS:

python main.py

Usage

The IDS will start monitoring network traffic once executed.

Detected threats will be logged and displayed.

Modify detection_rules.py to add custom detection logic.

Contribution

Contributions are welcome! If you want to add new detection rules or improve the system, follow these steps:

Fork the repository.

Create a new branch (feature/new-detection-rule).

Commit your changes and push to your branch.

Open a pull request.
