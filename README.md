# Net Sec Traffic Analyzer

This is a basic Python project I built so i could learn how network traffic works and attacks show up. It can:

- Capture packets with **Scapy** (needs admin privileges)
- Detect **ARP spoofing**, **DNS poisoning**, simple **port scans**, and basic **DoS spikes**
- Save everything to a CSV log
- Generate a quick **anomaly dashboard** report with charts (PNG images inside an HTML file)

> I’m a high school student (10th grade) and I wanted this to be clean, readable, and actually useful for practicing cybersecurity skills in a legal, safe way. If you're a random kid reading this maybe you will want to try this too

---

## Features
- **Live capture**: `scapy.sniff()` with a light parser → `data/logs.csv`
- **Detectors**
  - ARP spoofing: same IP seen with different MACs
  - DNS poisoning: conflicting answers for the same query or sudden IP flips with tiny TTLs
  - Port scan: many destination ports probed from the same source in a short window
  - DoS spike: packet rate spikes from a single source
- **Dashboard**: makes `reports/<timestamp>_report.html` with charts (matplotlib)
- **Config**: tweak thresholds in `config.yaml`

> **Ethics**: Only run this on networks you own or have permission to analyze.

---

## Quick Start

### 1) Setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Capture packets (needs admin/root)
```bash
python app.py capture --iface YOUR_INTERFACE
# Example on Linux/Mac: python app.py capture --iface en0
# Example on Windows:   python app.py capture --iface Wi-Fi
```
This writes rows to `data/logs.csv` as it captures.

### 3) Analyze + make a report
```bash
python app.py analyze --input data/logs.csv --report
```
This runs detectors and saves a dashboard HTML in `reports/`.

### 4) Try the sample data (no root needed)
```bash
python app.py analyze --input data/samples/synthetic_log.csv --report
```

---

## Project Structure
```
net-sec-traffic-analyzer/
  app.py                 # CLI (capture / analyze)
  requirements.txt
  config.yaml
  src/
    capture.py           # Sniffer using scapy
    analyze.py           # Loads CSV and runs detectors
    dashboard.py         # Builds charts & HTML report
    detectors/
      __init__.py
      arp_spoof.py
      dns_poison.py
      port_scan.py
      dos_spike.py
      utils.py
  data/
    logs.csv             # (created after capture)
    samples/
      synthetic_log.csv  # sample data for testing
  reports/               # auto-created for reports
  tests/
    test_detectors.py
  docs/
    design.md
    threat_model.md
    usage_tips.md
  LICENSE
  README.md
```

---

## What I learned / decisions I made
- Focused on **signal over noise**: a few detectors that are clear to explain
- Used **CSV** as the log format so it’s easy to inspect and graph
- Kept thresholds in a YAML file so it’s simple to tune on different networks
- The dashboard is static HTML so it can be shared without a server

---

## Legal & Safety
- Use on your own network or with explicit permission
- Don’t try to attack other people’s networks; this is for detection/learning

---

## License
MIT
