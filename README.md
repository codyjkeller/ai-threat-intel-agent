# 🛡️ AI Threat Intel Agent

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![OpenAI](https://img.shields.io/badge/AI-GPT--4-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

**An automated Threat Intelligence agent that monitors global security feeds, filters noise, and prioritizes risks specific to your tech stack.**

Instead of doom-scrolling Twitter or RSS feeds for hours, this agent:
1.  **Ingests** real-time data from CISA, The Hacker News, and BleepingComputer.
2.  **Analyzes** every article using GPT-4 to assign a "Risk Score" (1-10).
3.  **Filters** for relevance based on your defined "Watchlist" (e.g., Kubernetes, AWS, Zero-Day).
4.  **Reports** actionable intelligence in a clean dashboard and CSV export.

## 🚀 Key Features

* **Custom Watchlist:** Define your tech stack (e.g., "Azure", "Python") and the AI will flag relevant CVEs/breaches.
* **Auto-Scoring:** AI assigns a numerical Risk Score to every threat, filtering out "marketing fluff" news.
* **Executive Summaries:** Rewrites complex technical articles into 1-sentence impact statements.
* **Zero-Config Data:** Uses public RSS feeds—no expensive API keys (VirusTotal/AlienVault) required.

## 🛠️ Usage

### 1. Setup
```bash
git clone [https://github.com/codyjkeller/ai-threat-intel-agent.git](https://github.com/codyjkeller/ai-threat-intel-agent.git)
cd ai-threat-intel-agent
pip install -r requirements.txt

2. Configure Credentials
Copy the example environment file:
cp .env.example .env

3. Run the Agent
python src/main.py

📜 License
MIT
