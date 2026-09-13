# 🍯 HoneyGrid 2.0

> **Enterprise Deception Technology, Autonomous SOAR Containment & Threat Intelligence SOC Platform**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![Vercel](https://img.shields.io/badge/Deploy-Vercel-black.svg)](https://vercel.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1552%20%7C%20T1083%20%7C%20T1082-red.svg)](https://attack.mitre.org/)
[![SOAR](https://img.shields.io/badge/SOAR-Windows%20Firewall%20Containment-blueviolet.svg)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**HoneyGrid 2.0** is an enterprise-grade cyber deception and automated incident response platform. It generates multi-vector decoy assets (canary URLs, AWS IAM credentials, decoy Git repositories, KeePass databases, production `.env` files, and canary PDFs), monitors them via cloud sentinels and Windows filesystem tripwires, enriches incoming attacks with deep threat intelligence and hardware fingerprinting, and dispatches real-time SOC alerts to Discord and an interactive dark-mode web dashboard.

---

## 🚀 Key Upgrades in 2.0

* 🌐 **1-Click Vercel Cloud Deployment:** Deploy the public listener and SOC dashboard globally on Vercel serverless.
* 🖥️ **Dark-Mode SOC Web Dashboard:** Real-time attack feed, Leaflet world map with pulsing threat markers, and metric counters.
* 🧠 **Threat Intelligence & VPN/Tor Scoring:** Analyzes adversary IPs for commercial VPNs, Tor exit nodes, and hosting datacenters; computes an Adversary Risk Score (0–100%).
* 💻 **Browser & Hardware Fingerprinting:** Silently extracts GPU renderer (WebGL), screen resolution, CPU cores, timezone, and WebRTC local LAN IP leaks when an adversary visits a decoy link.
* 🌿 **Git & KeePass Decoys:** Authentic-looking `.git/config` canary remotes and KeePass 2.x (`.kdbx`) password vaults.
* 🛡️ **SOAR Host Containment Playbook:** Automated Windows Firewall isolation to block hostile IPs on command.
* 📑 **Executive Post-Mortem Report Generator:** Auto-generates C-suite incident reports with Root Cause Analysis, IOC tables, and remediation steps.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        Vercel Serverless / Cloud Sentinel                              │
│                                                                                        │
│   ┌────────────────────────────────┐         ┌─────────────────────────────────────┐   │
│   │   Canary Sentinel Listener     │         │   Incident Response Dashboard       │   │
│   │   - Public /t/{token_id}       │         │   - Dark-mode SOC Interface         │   │
│   │   - Browser Fingerprint Probe  │         │   - Live World Attack Map (Leaflet) │   │
│   │   - WebRTC Local IP Collector  │         │   - Incident Scoping & Timeline     │   │
│   │   - Threat Intel & VPN Scorer  │         │   - Executive Report Generator      │   │
│   └───────────────┬────────────────┘         └──────────────────┬──────────────────┘   │
└───────────────────┼─────────────────────────────────────────────┼──────────────────────┘
                    │                                             │
                    v                                             v
        ┌───────────────────────┐                     ┌───────────────────────┐
        │  Discord SOC Channel  │                     │   Local Windows Agent │
        │  - Exact IP + VPN tag │                     │   - Honeyfile Watcher │
        │  - Hardware / GPU info│                     │   - Git & KeePass Traps│
        │  - Map & Abuse Score  │                     │   - Firewall Blocker  │
        └───────────────────────┘                     └───────────────────────┘
```

---

## 🎯 Supported Decoy Vectors

| Decoy Vector | Generated Asset | Trigger Mechanism |
| :--- | :--- | :--- |
| **Web Canary** | Cryptographic URL endpoint | Attacker visits or curls the URL. |
| **AWS IAM Key** | `~/.aws/credentials` (`AKIA...`) | Attacker attempts to authenticate against internal gateway. |
| **Decoy Git Repo** | `.git/config` with canary remote | Attacker runs `git pull` or `git fetch`. |
| **KeePass Vault** | `Corporate_Passwords_2026.kdbx` | Attacker opens, moves, or copies the database. |
| **Decoy `.env`** | `.env.production.backup` | Attacker scrapes or tests internal API synchronization URLs. |
| **Canary PDF** | `Executive_Salaries_Q4_2026.pdf` | Document opens and executes remote beacon. |
| **Honeyfile** | Local filesystem file tripwire | Windows filesystem watcher detects read/modify events. |

---

## 🛡️ MITRE ATT&CK Matrix

* **Credential Access (`T1552.001`):** Credentials in Files (Decoy `.env`, AWS credentials, KeePass vault).
* **Discovery (`T1083`):** File and Directory Discovery (Local honeyfiles).
* **Discovery (`T1082`):** System Information Discovery (Canary endpoints).
* **Lateral Movement (`T1021`):** Remote Services (Canary API authentication probes).

---

## ⚡ Quickstart

### 1. Installation
```powershell
git clone https://github.com/Zine007MHIDRA/HoneyGrid.git
cd HoneyGrid

python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate # Linux / macOS

pip install -r requirements.txt
```

### 2. Configure Environment
```powershell
cp .env.example .env
```
Edit `.env`:
```ini
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
HONEYGRID_BASE_URL=http://localhost:8000
```

### 3. Launch the SOC Web Dashboard
```powershell
python cli.py dashboard
```
Opens your browser at **`http://localhost:8000/dashboard`** with the live world attack map and telemetry feed!

---

## 📖 CLI Reference

```powershell
# Generate Decoys
python cli.py generate --type web --label "Wiki-Bookmark"
python cli.py generate --type git --label "Deploy-Scripts"
python cli.py generate --type keepass --label "Master-Vault"
python cli.py generate --type aws --label "Prod-Backup-Key"
python cli.py generate --type env --label "Staging-Secrets"
python cli.py generate --type pdf --label "Executive-Compensation-2026"
python cli.py generate --type file --path "C:\Users\Admin\Desktop\secrets.txt"

# List Active Traps & Incident Logs
python cli.py list-tokens
python cli.py list-incidents

# Test Alert Pipeline (with Geolocation & Threat Scoring)
python cli.py test-alert

# SOAR: Isolate Attacker IP via Windows Firewall
python cli.py isolate-ip --ip 198.51.100.77
python cli.py isolate-ip --ip 198.51.100.77 --dry-run
python cli.py unblock-ip --ip 198.51.100.77
```

---

## 🌐 Deploying to Vercel (1-Click Cloud Hosting)

HoneyGrid is pre-configured with `vercel.json` and a serverless entrypoint (`api/index.py`):

1. Push your repository to GitHub.
2. Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
3. Import your **`HoneyGrid`** repository.
4. Under **Environment Variables**, add:
   * `DISCORD_WEBHOOK_URL`: Your Discord webhook URL.
   * `HONEYGRID_BASE_URL`: `https://your-honeygrid-app.vercel.app`
5. Click **Deploy**!

Your SOC dashboard and canary listener will now be live on a public HTTPS URL accessible from anywhere in the world.

---

## 🔴 Red Team Verification Script

Run the automated adversary simulation:
1. In Terminal 1: `python cli.py listen`
2. In Terminal 2: `python simulate_adversary.py`

This will simulate:
* Phase 1: Automated reconnaissance (`curl`).
* Phase 2: Targeted exploitation behind a proxy (`198.51.100.77`), unmasking the public IP and calculating threat scores.
* Phase 3: Web secret scraping (`/.env`).
* Phase 4: Browser hardware fingerprinting (GPU, screen, WebRTC LAN leak).

---

## 👨‍💻 Author & Portfolio Context
Designed and engineered as a high-impact **Incident Response & Deception Engineering** portfolio showcase:
* Active Defense & Honeytoken Engineering
* Threat Telemetry, ASN Mapping & Hardware Profiling
* SOAR Incident Containment & Windows Firewall Playbooks
* Full-Stack SOC Telemetry Dashboard & Serverless Deployment
