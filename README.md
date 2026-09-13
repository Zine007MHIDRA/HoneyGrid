# 🍯 HoneyGrid

> **High-Fidelity Deception Technology & Honeytoken Platform for Incident Responders & Threat Hunters**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1552%20%7C%20T1083-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**HoneyGrid** is an active defense and deception engineering framework designed for Windows and cloud environments. It generates, deploys, and monitors multi-vector honeytokens (canary URLs, decoy AWS credentials, sensitive `.env` files, canary PDF documents, and filesystem tripwires). 

When an adversary breaches a perimeter or conducts internal reconnaissance, touching any HoneyGrid asset captures forensics (unmasked public IP, proxy chain, client signatures, geolocation) and dispatches real-time alerts to a Discord Incident Response channel.

---

## 🏗️ Architecture

```
                                  +---------------------------------------+
                                  |             HoneyGrid CLI             |
                                  |    (Token Gen, Deploy, Simulation)    |
                                  +-------------------+-------------------+
                                                      |
                                                      v
  +--------------------------+          +---------------------------+          +-------------------------+
  |    Honeytoken Assets     | -------> |   HoneyGrid Core Engine   | <------- |  Decoy Watcher Service  |
  |  - Web / API Canaries    |          |  - SQLite Token Registry  |          |  - Windows File Watcher |
  |  - Decoy AWS Credentials |          |  - IP Extraction Engine   |          |    (Read/Modify Trip)   |
  |  - Decoy .env Configs    |          |  - GeoIP & ASN Enrichment |          +-------------------------+
  |  - Canary PDF Documents  |          +-------------+-------------+
  +--------------------------+                        |
                                                      v
                                    +-----------------------------------+
                                    |     Alert Dispatcher Service      |
                                    |  - Discord Rich SOC Embed Alert   |
                                    |  - Forensic Incident Log (SQLite) |
                                    +-----------------------------------+
```

---

## 🎯 Key Capabilities

### 1. Multi-Vector Decoy Generation
* **Web / API Canaries:** Unique cryptographic tokens embedded into URL endpoints.
* **AWS IAM Honeytokens:** Authentic-looking `~/.aws/credentials` with valid key structures (`AKIA...`) wired to beacon callbacks.
* **Decoy `.env` Files:** Realistic production secrets (fake database strings, Stripe keys) containing canary sync URLs.
* **Canary PDF Documents:** Formatted executive documents (e.g. `Executive_Salaries_2026.pdf`) containing tracking beacons.
* **Filesystem Honeyfiles:** Local tripwires on Windows; alerts when a file is opened, copied, or modified.

### 2. High-Precision Attacker IP Unmasking
* **Exact Public IP Extraction:** Inspects raw TCP sockets as well as reverse proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`).
* **Real-Time Geolocation & ASN:** Automatically resolves Country, City, Region, ISP, and Autonomous System Number (ASN).
* **Direct Google Maps Pin:** Dispatches exact coordinate pins directly into the alert.
* **Client Fingerprinting:** Detects whether the attacker used `cURL`, `Python Requests`, `Burp Suite`, `Nmap`, or a modern browser.

### 3. Immediate SOC Alerting (Discord Webhook)
Each tripped token triggers an embed formatted for rapid incident triage:
* 🎯 **Prominent Attacker IP & Geolocation**
* 📍 **Clickable Map Link**
* 🏷️ **Asset Name & Token Identifier**
* 🛠️ **Detected Tool & User-Agent**
* 🛡️ **MITRE ATT&CK Classification**

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | Description in HoneyGrid |
| :--- | :--- | :--- |
| **Credential Access** | `T1552.001` - Credentials in Files | Decoy `.env` files and AWS credential sets placed in common repos or drives. |
| **Discovery** | `T1083` - File and Directory Discovery | Honeyfiles placed on desktop or shared drives to detect unauthorized scanning. |
| **Discovery** | `T1082` - System Information Discovery | Attacker probing internal endpoints or discovery URLs. |
| **Lateral Movement** | `T1021` - Remote Services | Probes against canary API auth endpoints. |

---

## 🚀 Quickstart Guide

### 1. Installation
Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/Zine007MHIDRA/HoneyGrid.git
cd HoneyGrid

python -m venv venv
venv\Scripts\activate      # On Windows
# source venv/bin/activate # On Linux/macOS

pip install -r requirements.txt
```

### 2. Configure Environment Secrets
Copy the example environment file and add your Discord Webhook:

```bash
cp .env.example .env
```

Edit `.env`:
```ini
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_TOKEN
HONEYGRID_BASE_URL=http://localhost:8000
```

### 3. Test Webhook Connection
Verify that your Discord alert pipeline is operational:

```bash
python cli.py test-alert
```

---

## 📖 Usage & Workflow

### 1. Generate Decoys & Honeytokens

```bash
# Generate an HTTP Canary URL
python cli.py generate --type web --label "Marketing-Share-Link"

# Generate decoy AWS Credentials
python cli.py generate --type aws --label "Prod-Backup-AWS-Key"

# Generate a decoy .env file
python cli.py generate --type env --label "Staging-Env-Secrets"

# Generate a Canary PDF Document
python cli.py generate --type pdf --label "Executive-Compensation-2026"

# Register a local honeyfile tripwire
python cli.py generate --type file --path "C:\Users\Admin\Desktop\passwords.txt" --label "Desktop-Decoy"
```

### 2. Start the Sentinel Listener

```bash
python cli.py listen
```
The listener will run on `0.0.0.0:8000`, monitoring incoming canary hits and watching registered honeyfiles.

### 3. Review Incidents & Forensics

```bash
# List all active deployed tokens
python cli.py list-tokens

# View real-time forensic incident logs
python cli.py list-incidents
```

---

## 🔴 Red Team Verification (Adversary Simulation)

HoneyGrid includes a built-in automated adversary emulator to prove detection capabilities:

1. In Terminal 1, start the listener:
   ```bash
   python cli.py listen
   ```
2. In Terminal 2, run the adversary simulation:
   ```bash
   python simulate_adversary.py
   ```
The simulation will:
* Simulate an automated scanner probe (`curl` signature).
* Simulate an external attacker behind a proxy, proving that **HoneyGrid extracts the real public IP**.
* Simulate discovery and secret scraping of a web `/.env` file.
* Immediately populate your Discord channel with real-time incident embeds!

---

## 🔒 Security Best Practices
* **Zero Real Secrets:** All generated keys and credentials are syntactically valid decoys.
* **Excluded from Version Control:** `.env` is strictly ignored in `.gitignore` to prevent leaking webhook tokens.
* **Deceptive Response Codes:** The listener returns `401 Unauthorized` or transparent 1x1 tracking GIFs to avoid alerting attackers that they were trapped.

---

## 👨‍💻 Author & Contributions
Built as a Purple Team & Deception Engineering portfolio project demonstrating:
* Active Defense & Honeytoken Engineering
* Threat Telemetry & Client Fingerprinting
* Incident Response Triage Automation & SOAR Webhooks
