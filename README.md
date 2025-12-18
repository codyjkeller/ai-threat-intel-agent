# 🛡️ AI Threat Intelligence Agent

### Automated CISA Vulnerability Analysis & Executive Briefing

[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Source](https://img.shields.io/badge/Data_Source-CISA_KEV-red.svg)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### 📖 Overview
This agent is an automated Intelligence pipeline designed to bridge the gap between **Technical Alerts** and **Executive Strategy**.

Instead of flooding security teams with raw CVE data, this agent:
1.  **Ingests** real-time threat data from the **CISA Known Exploited Vulnerabilities (KEV)** catalog.
2.  **Filters** noise to identify only the most recent active exploits.
3.  **Synthesizes** an "Executive Briefing" using **GenAI (OpenAI)** to translate technical jargon into business risk.

### ⚡ Feature Highlights
* **Real-Time CISA Feed:** Pulls directly from the US Government's authoritative source for active exploits.
* **Rich Terminal UI:** Professional CLI dashboard for SecOps monitoring.
* **Fail-Safe Architecture:** Includes a deterministic fallback mode if the AI service is unavailable, ensuring the pipeline never breaks during critical incidents.

---

### 🛠️ Quick Start

**1. Clone the Repository**
```bash
git clone [https://github.com/codyjkeller/ai-threat-intel-agent.git](https://github.com/codyjkeller/ai-threat-intel-agent.git)
cd ai-threat-intel-agent
