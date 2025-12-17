# AI Threat Intel Agent

## 📌 Overview
An automated intelligence agent designed to solve "Alert Fatigue."

Instead of spamming the security team with raw CVE feeds, this agent:
1.  **Ingests** data from high-fidelity sources (CISA, NVD, Microsoft, AWS).
2.  **Filters** noise using strict risk logic (CVSS > 7.0 or Active Exploitation).
3.  **Summarizes** relevance using GenAI.
4.  **Delivers** a "Plain English" executive briefing to Slack/Email.

## 🧠 The "Smart Filter" Logic
The agent does not simply forward news. It applies a **Risk Decision Matrix**:

| Condition | Action | Rationale |
| :--- | :--- | :--- |
| **CVSS Score >= 7.0** | ✅ **ALERT** | High/Critical severity requires immediate patching (SLA < 7 Days). |
| **Source = CISA KEV** | ✅ **ALERT** | "Known Exploited" means active attacks are happening now. |
| **CVSS Score < 7.0** | 🔇 **DROP** | Medium/Low risks are handled via standard monthly patch cycles. |

## 📂 Repository Contents
* [`/config/feeds.json`](config/feeds.json): Configuration of 9+ sources (Gov, Cloud, OSINT) categorized by trust level.
* [`/agent/daily_briefing.py`](agent/daily_briefing.py): The Python engine that fetches, filters, and summarizes the intel.

## 🚀 Usage Demo
```bash
python agent/daily_briefing.py
