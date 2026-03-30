# Network Traffic Anomaly Detector

A Python-based network traffic analysis tool that builds behavioral baselines from real packet captures, detects anomalous flows using machine learning, and maps findings to MITRE ATT&CK techniques.

---

## What it does

Most intrusion detection tools rely on signatures — known bad IPs, known malware hashes. This tool takes a different approach: it learns what normal traffic looks like for a given host, then flags flows that deviate from that baseline.

The pipeline works in four stages:

1. **Capture** — reads raw packets from a PCAP file or live interface using scapy
2. **Feature extraction** — groups packets into flows and extracts numerical features (duration, byte volume, packet count, inter-arrival timing, SYN count, port entropy)
3. **Anomaly detection** — trains an Isolation Forest model on stored baseline flows and scores new traffic against it
4. **MITRE mapping** — enriches flagged flows with the most likely ATT&CK tactic and technique, then writes a structured JSON report

---

## Detection approach

The core model is scikit-learn's **Isolation Forest** — an unsupervised algorithm well suited to anomaly detection because it doesn't require labeled attack data. It isolates observations by randomly partitioning features; anomalous flows (unusual timing, unexpected byte volumes, high SYN counts) are isolated faster and receive lower scores.

Features used per flow:

| Feature | Why it matters |
|---|---|
| `duration` | Beaconing connections are often very short and regular |
| `packet_count` | Scanning generates many small flows |
| `total_bytes` | Exfiltration shows large outbound transfers |
| `avg_packet_size` | C2 traffic tends toward small, uniform packets |
| `avg_inter_arrival` | Regular intervals suggest automated/beaconing behavior |
| `unique_dst_ports` | High count indicates port scanning |
| `syn_count` | Repeated SYNs suggest brute force or scanning |

---

## MITRE ATT&CK mapping

Flagged flows are automatically tagged with the most likely technique:

| Technique | ID | Trigger condition |
|---|---|---|
| Application Layer Protocol | T1071 | Small packets, short inter-arrival, regular cadence |
| Exfiltration Over Alternative Protocol | T1048 | Large byte transfer in short duration |
| Network Service Scanning | T1046 | High unique destination port count |
| Brute Force | T1110 | High SYN count |
| Non-Standard Port | T1571 | Traffic on uncommon sub-1024 port |

---

## Real-world results

This tool was developed alongside a companion project — a live SSH/HTTP honeypot deployed on a Hetzner cloud VPS (see [github.com/gianniskinalis/honeypot](https://github.com/gianniskinalis/honeypot)).

The honeypot ran for 48 hours against the open internet with no authentication hardening, collecting real attack traffic. The IOC extractor produced the following findings:

**SSH (port 22)**
- 30,243 total connections from 542 unique IPs across 30+ countries
- A single IP (46.62.145.156) was responsible for 23,205 attempts — sustained automated scanning
- 96% of all login attempts targeted the `root` account, consistent with mass credential stuffing
- Top passwords tried: `123456`, `admin`, `1234`, `password`, `qwerty`

**HTTP (port 80)**
- 14,321 requests from 398 unique IPs
- Attackers probed for `/.env` (exposed credentials), `/wp-content/plugins/hellopress/wp_filemanager.php` (vulnerable WordPress plugin), and known webshell paths including `/gptsh.php` and `/bolt.php`

**What the anomaly detector would flag in this traffic:**

| Flow pattern | Expected MITRE tag | Reason |
|---|---|---|
| 46.62.145.156 repeated SYN bursts | T1110 — Brute Force | High SYN count, rapid inter-arrival |
| Webshell path probing | T1071 — Application Layer Protocol | Small uniform HTTP requests at regular intervals |
| /.env and credential file scanning | T1083 — File and Directory Discovery | Repeated probes to sensitive paths |
| Unknown user agents (`libredtail-http`) | T1071 — Application Layer Protocol | Non-browser tooling making automated requests |

The combination of behavioral baselining and MITRE mapping means this tool goes beyond simple IP blocklisting — it surfaces *what attackers are doing*, not just *who they are*.

---

## Sample output
```
[*] Loaded 136 packets
[*] Parsed 132 IP packets (4 non-IP skipped)
[*] Grouped 132 packets into 34 flows
[*] Baseline trained on 34 flows
[*] Scored 34 flows — 2 anomalies detected

======================================================================
  THREAT REPORT SUMMARY
======================================================================
  Total flows analysed : 34
  Anomalies detected   : 2

 [001] 10.0.2.15 -> 104.18.27.120 (score: -0.015)
       [!] Command & Control | T1071 - Application Layer Protocol
           Small regular packets suggesting beaconing behavior

 [002] 10.0.2.15 -> 157.240.0.1 (score: -0.0074)
       [!] Unclassified anomaly
           Anomalous behavior detected but no specific technique matched
```

Reports are saved as timestamped JSON files in `reports/` with full feature vectors and MITRE tags.

---

## Installation
```bash
git clone https://github.com/gianniskinalis/network-anomaly-detector.git
cd network-anomaly-detector
pip install -r requirements.txt
```

**Requirements:** Python 3.10+, root/sudo access for live capture

---

## Usage

**Analyse a PCAP file:**
```bash
python3 main.py pcaps/your_capture.pcap
```

**Capture live traffic (requires sudo):**
```bash
sudo tcpdump -i eth0 -w pcaps/capture.pcap
# Ctrl+C to stop, then:
python3 main.py pcaps/capture.pcap
```

The tool accumulates flows in `data/baseline.db` across runs — the more traffic it sees, the more accurate the baseline becomes.

---

## Project structure
```
network-anomaly-detector/
├── capture/        # Packet ingestion and parsing (scapy)
├── features/       # Flow grouping and feature extraction
├── baseline/       # SQLite persistence and baseline storage
├── detection/      # Isolation Forest scoring
├── mapping/        # MITRE ATT&CK technique mapping
├── report/         # JSON report generation
├── main.py         # Entry point
└── requirements.txt
```

---

## Stack

- **Python 3.12**
- **scapy** — packet capture and parsing
- **scikit-learn** — Isolation Forest anomaly detection
- **SQLite** — flow storage and baseline persistence
- **numpy / pandas** — feature vector construction

---

## Disclaimer

This tool is intended for educational purposes and authorized security research only. Only run it against networks and systems you own or have explicit permission to monitor. The author is not responsible for any misuse or damage caused by this tool.

## Author

**Giannis Kinalis**
*Cybersecurity Enthusiast*

- **GitHub:** [gianniskinalis](https://github.com/gianniskinalis)
- **LinkedIn:** [Ioannis Kinalis](https://linkedin.com/in/ioannis-kinalis)