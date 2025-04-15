# Automated Threat Detection and Response System (ATDRS)

## Description
This system continuously monitors network traffic, detects suspicious activity, and sends email alerts in real-time. It helps businesses prevent unauthorized access and mitigate potential cyber threats.

## Features
- Monitors network packets using Scapy
- Identifies suspicious IP addresses
- Sends real-time email alerts
- Easy to configure and deploy

## Installation
```bash
pip install scapy
```

## Usage
```bash
sudo python3 ATDRS.py
```

## Configuration
Edit the following variables in the script:
- `SUSPICIOUS_IPS`: List of IPs to monitor
- `ALERT_EMAIL`: Email address to receive alerts
- `EMAIL_USERNAME` and `EMAIL_PASSWORD`: SMTP email credentials
- `SMTP_SERVER` and `SMTP_PORT`: Email server settings

## Disclaimer
This project is for educational purposes only. Ensure compliance with local laws before monitoring network traffic.
