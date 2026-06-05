# 🐺 BlackHound K9 (Alpha)

![Version](https://img.shields.io/badge/version-Alpha_V3.6-red)
![Docker](https://img.shields.io/badge/Docker-Containerized-blue)
![Stack](https://img.shields.io/badge/Stack-React%20%7C%20FastAPI%20%7C%20Go-black)
![License](https://img.shields.io/badge/license-GPLv3-red)

An open-source, AI-powered Bug Bounty Recon Dashboard designed to eliminate terminal fatigue and automate report generation.

<img width="1904" height="1563" alt="Screenshot 2026-06-05 at 22-30-57 Project Sentinel" src="https://github.com/user-attachments/assets/139f70f1-8270-40d4-b577-880ef24857b0" />


## 🚀 The Problem
Modern bug bounty hunting requires chaining together 10 different CLI tools, managing chaotic terminal windows, and filtering through 60,000+ false-positive directories just to find one vulnerability. 

## 🛠️ The Solution
BlackHound K9 orchestrates industry-standard Go tools into a highly OPSEC-safe pipeline, streams the output to a clean React dashboard, and uses an AI Engine (Bring Your Own Key) to triage findings and write your executive reports for you.

### Features
- **Deterministic Pipeline:** `subfinder` ➔ `dnsx` ➔ `naabu` ➔ `httpx` ➔ `katana`/`gau` ➔ `ffuf` ➔ `nuclei`.
- **WAF Evasion & OPSEC:** Configurable rate-limiting, custom Safe Harbor headers, and "Sniper Mode" to test only Critical/High CVEs without triggering Cloudflare blocks.
- **Context-Aware AI Triage:** Filters out the noise. The AI knows that port 80 is `Info`, but port 22 on a `dev.` subdomain is `High`.
- **Automated Report Generation:** The AI assesses the attack surface and writes an Executive Summary with potential exploit chains, ready to be copy-pasted into HackerOne.

<img width="1171" height="682" alt="image(8)(1)" src="https://github.com/user-attachments/assets/deaac921-ca44-4fec-b3fe-1d92028d1a22" />

## 🚀 Quick Start (Docker)

BlackHound K9 is fully containerized. You do not need to install Go, Python, or any security tools on your host machine.

```bash
# 1. Clone the repository
git clone https://github.com/BlackHound-Security/BlackHound-K9.git
cd BlackHound-K9

# 2. Build and launch the containers
docker compose up -d --build

# 3. Access the Command Center
# Open your browser and navigate to:
http://localhost:5173
```

## ⚠️ Legal Disclaimer
BlackHound K9 is an offensive security tool designed STRICTLY for authorized bug bounty hunting and penetration testing. Running these tools against targets without explicit permission is illegal. You accept full responsibility for your actions.
