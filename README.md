# FW Traffic - Firewall Packet Flow Simulator

A Flask web application that simulates the packet-processing pipeline of four major firewall brands: FortiGate, Check Point, Palo Alto (PAN-OS), and Cisco FTD. Input traffic characteristics and get a detailed step-by-step walkthrough of each security inspection stage with CLI-like log lines and verdicts.

## Supported Firewalls
- FortiGate
- Check Point
- Palo Alto (PAN-OS)
- Cisco FTD

## Setup
```bash
pip install -r requirements.txt
python app.py
```