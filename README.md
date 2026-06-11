# 🐺 BlackHound K9 (Alpha V3.6)

![Version](https://img.shields.io/badge/version-Alpha_V3.6-red)
![Docker](https://img.shields.io/badge/Docker-Containerized-blue)
![Stack](https://img.shields.io/badge/Stack-React%20%7C%20FastAPI%20%7C%20Go-black)
![License](https://img.shields.io/badge/license-GPLv3-red)

**Stop staring at terminals. Let the Hound hunt.** 
An open-source, AI-orchestrated Attack Surface Management (ASM) and DAST platform that turns chaotic terminal noise into paid bounties.

<img width="1904" height="1563" alt="Screenshot 2026-06-05 at 22-30-57 Project Sentinel" src="https://github.com/user-attachments/assets/139f70f1-8270-40d4-b577-880ef24857b0" />

## 🛑 The Problem
The bug bounty industry is stuck in the past. You are wasting hours writing `grep` and `awk` spaghetti scripts, managing 12 different terminal windows, and paying $100/month for "premium" SaaS wrappers that just run Subfinder in the cloud. 

Worse, you are suffering from **Alert Fatigue**. Digging through 66,000 false-positive 403 errors and endless `/api/user/[uuid]` endpoints blinds you to the actual vulnerabilities that pay out. Terminal fatigue kills bugs.

## 🗡️ The Solution
**BlackHound K9 isn't a bash script. It is an automated Red Team operator.** 
It orchestrates an arsenal of the industry's most lethal Go tools into a highly OPSEC-safe pipeline, maps the data to a glowing visual heatmap, fires deep-web exploits, and uses an AI Engine to write your HackerOne reports while you sleep.

### 🔥 V3.14 Arsenal & Features

*   🗺️ **The Attack Surface Heatmap:** A dynamic, hierarchical visual tree of the target. It automatically collapses noisy UUIDs/hashes into `[ID]` folders, and makes parent folders **glow red** if a critical vulnerability is buried deep inside them. Your eyes are guided straight to the money.
*   🖨️ **The Bounty Printer (Deep DAST):** K9 doesn't just scratch the surface. It strips endpoints from `katana`/`gau`, feeds them into `x8` to find hidden HTTP parameters, and automatically passes them to `dalfox` for blind XSS injection and `nuclei` for SQLi fuzzing. 
*   📸 **Visual Recon & Cloud Scraping:** Automatically snaps screenshots of every live host via `gowitness`. Hashes favicons via `mmh3` to bypass stripped headers, fingerprints WAFs with `WAFW00F`, and hunts for exposed AWS/GCP buckets using `cloud_enum`.
*   🥷 **Weaponized OPSEC:** Configurable rate-limiting, custom Safe Harbor headers (`X-Bug-Bounty`), and a Nuclei "Sniper Mode" to test only Critical/High CVEs without triggering Cloudflare tarpits.
*   🧠 **Executive AI Triage (BYOK):** The AI filters out the garbage. It knows port 80 is `Info`, but port 22 on a `dev.` subdomain is `High`. It assesses the attack chain and writes an Executive Summary ready to be copy-pasted into your bug report.
*   💤 **"Set & Forget" Webhooks:** Fire up a massive Carpet Bomb scan, close your laptop, and let K9 send the final AI report and Critical findings directly to your Slack or Discord webhook.

<img width="1171" height="682" alt="image(8)(1)" src="https://github.com/user-attachments/assets/deaac921-ca44-4fec-b3fe-1d92028d1a22" />

## 🚀 Quick Start (Docker)
BlackHound K9 is 100% containerized. You do not need to install Python or manage dependency hell on your host machine.

```bash
# 1. Clone the repository
git clone https://github.com/BlackHound-Security/BlackHound-K9.git
cd BlackHound-K9

# 2. Build and launch the hounds (Detached Mode)
docker compose up -d --build

# 3. Access the Command Center
# Open your browser and navigate to:
http://localhost:5173
```

## ⚠️ Legal Disclaimer
BlackHound K9 is an offensive security tool designed STRICTLY for authorized bug bounty hunting, penetration testing, and security research. Running these tools against targets without explicit, written permission is illegal. BlackHound Security LLC and the contributors of this project assume no liability and are not responsible for any misuse or damage caused by this program. You accept full responsibility for your actions.
