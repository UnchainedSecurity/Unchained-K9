# 🐺 BlackHound K9 (Alpha)

![Version](https://img.shields.io/badge/version-Alpha_V3.6-red)
![Docker](https://img.shields.io/badge/Docker-Containerized-blue)
![Stack](https://img.shields.io/badge/Stack-React%20%7C%20FastAPI%20%7C%20Go-black)
![License](https://img.shields.io/badge/license-MIT-blue)

**BlackHound K9** is a local-first, AI-powered Offensive Security orchestration suite. It chains 10 battle-tested Go tools into a highly resilient, deterministic pipeline, strips away terminal noise, and uses Context-Aware AI to triage tens of thousands of findings into actionable bug bounty reports.

## ⚡ The Problem It Solves
Modern bug bounty reconnaissance generates massive "Alert Fatigue." Running `httpx`, `ffuf`, and `nuclei` against a wildcard target can yield 60,000+ lines of raw JSON, littered with WAF false positives and dead endpoints. 

BlackHound K9 automates the entire pipeline, catches Cloudflare/WAF redirects, gracefully handles tool crashes without leaving zombie processes, and feeds normalized data to a local or cloud LLM. The AI writes an Executive Assessment and separates your actual Vulnerabilities from your Infrastructure Profile.

## 🛠️ The Arsenal (10-Tool Pipeline)
1. **OSINT:** `subfinder`, `theHarvester`, `dnsx`
2. **Probing:** `naabu` (Port Scanning), `httpx` (Live Web Servers)
3. **Crawling & Fuzzing:** `whatweb`, `gau`, `katana`, `ffuf` (with WAF Auto-Calibration)
4. **Vulnerability Scanning:** `nuclei` (Sniper, Normal, or Carpet Bomb depths)
5. **AI Triage:** OpenAI-Compatible SDK (Connects to `llama.cpp` or OpenRouter)

## ✨ Enterprise Features
* **Safe Harbor Compliant:** Built-in rate limiting (RPS), custom concurrent thread controls, and dynamic Custom Header injection (e.g., `X-Bug-Bounty: Username`) to comply with strict HackerOne/Bugcrowd RoE policies.
* **Engine Resilience:** 
  * **Zombie Killer:** Utilizes Linux Process Group isolation (`os.killpg`) so cancelled scans don't leave orphaned Go threads burning your CPU.
  * **Graceful Degradation:** Strict timeouts and auto-retries. If a tool hangs on a WAF, K9 safely kills it and passes the baton to the next tool.
* **Context-Aware AI:** The LLM prompt is engineered with strict bug bounty heuristics. It extracts pure technology fingerprints into an Infrastructure Profile, and writes an Executive Attack Plan for vulnerabilities.
* **Live React Dashboard:** A sleek "Bloody Red" UI featuring a 60FPS WebSocket terminal, Tabbed navigation, data pagination, severity sorting, and 1-click Markdown/JSON exports.

---

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

## ⚙️ AI Engine Configuration
BlackHound K9 is Provider Agnostic. You can use your own local GPU or route through the cloud via the Advanced Settings UI:
* **Cloud Models (Recommended):** Point the API URL to `https://openrouter.ai/api/v1`, enter your API key, and use frontier models like `anthropic/claude-opus-4.8` or `nvidia/nemotron-3-ultra-550b-a55b`.
* **Local Models:** Point the API URL to `http://host.docker.internal:11434/v1` (Ollama) or your `llama.cpp` server's address.

## ⚠️ Legal Disclaimer
**BlackHound K9 is built STRICTLY for authorized penetration testing and bug bounty hunting.** 
Running these tools against targets without explicit, documented permission is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program. By deploying this software, you accept full responsibility for your actions.
