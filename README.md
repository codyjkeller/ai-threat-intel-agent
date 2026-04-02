# Threat Intel Portal

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

**A self-hosted threat intelligence digest service.** Subscribe to security topics, product-specific advisories, and privacy legislation — receive personalized briefings at your chosen frequency.

> **Disclaimer:** This service aggregates publicly available threat intelligence for informational purposes only. Subscribing to product-specific alerts does not indicate or acknowledge use of those products in your environment. This is not a substitute for a formal threat intelligence program. Use at your own risk. See [full disclaimer](#disclaimer) below.

## What It Does

Think TLDR newsletter, but for cybersecurity and privacy — self-hosted, customizable, and product-aware.

Users sign up, pick the topics and products they care about, and receive a curated digest via the API (email integration planned). Sources are all public: CISA KEV, NVD/CVE, vendor security advisories, and security/privacy news RSS feeds.

**Topics** cover broad categories: ransomware, zero-days, cloud security, nation-state threats, US privacy legislation, AI regulation, and more.

**Products** let you subscribe to alerts for specific tools: AWS, Azure, Okta, CrowdStrike, Palo Alto, Microsoft 365, GitHub, and others. When a CVE or advisory drops for a product you track, it shows up in your digest.

**Frequency** is user-controlled: daily, weekly, or monthly.

## Features

- **Feed Ingestion:** CISA KEV catalog, NVD CVE API (CVSS 7.0+), RSS feeds (Krebs, Bleeping Computer, The Record, IAPP, vendor advisories)
- **User Accounts:** Signup, login, JWT auth
- **Subscription System:** Subscribe to topics (ransomware, privacy law, etc.) and/or specific products (AWS, Okta, etc.)
- **Digest Builder:** Personalized digests grouped by severity (Critical, High, News)
- **Background Scheduler:** Automatic feed ingestion every 4 hours (configurable), ensuring at least 2 refreshes per workday
- **Docker Ready:** Single-container deployment, Portainer-compatible
- **Privacy & Compliance News:** US state privacy legislation, GDPR, AI regulation tracking

## Quick Start

### Local Development

```bash
git clone https://github.com/codyjkeller/ai-threat-intel-agent.git
cd ai-threat-intel-agent
pip install -r requirements.txt
cp .env.example .env  # edit JWT_SECRET
uvicorn src.main:app --reload
```

API docs at `http://localhost:8000/docs`

### Docker (Production / Home Lab)

```bash
git clone https://github.com/codyjkeller/ai-threat-intel-agent.git
cd ai-threat-intel-agent
cp .env.example .env  # edit JWT_SECRET
docker compose up -d
```

Runs on port `8400`. Point your Cloudflare Tunnel or reverse proxy to `http://<host-ip>:8400`.

### Portainer

Create a new stack in Portainer, paste the `docker-compose.yml` content, set environment variables, and deploy.

## API Reference

All endpoints under `/api/v1`. Auth endpoints are public; everything else requires `Authorization: Bearer <token>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/signup` | Create account |
| POST | `/api/v1/auth/login` | Get JWT token |
| GET | `/api/v1/me` | Current user profile |
| GET | `/api/v1/topics` | List available topics |
| GET | `/api/v1/products` | List available products |
| PUT | `/api/v1/subscriptions` | Update subscriptions + frequency |
| GET | `/api/v1/digest/preview` | Preview next digest |
| GET | `/api/v1/feed` | Browse all feed items (filterable) |
| GET | `/health` | Health check |
| GET | `/disclaimer` | Legal disclaimer |

## Project Structure

```text
ai-threat-intel-agent/
├── src/
│   ├── main.py              # FastAPI app + scheduler
│   ├── api/routes.py        # API endpoints
│   ├── models/
│   │   ├── database.py      # SQLAlchemy models
│   │   └── seed.py          # Default topics, products, feed sources
│   ├── feeds/ingest.py      # CISA KEV, NVD, RSS ingestion
│   └── services/
│       ├── auth.py           # Password hashing, JWT
│       └── digest.py         # Digest builder
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
└── README.md
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | (required) | JWT signing key |
| `INGEST_INTERVAL_HOURS` | `4` | Hours between feed ingestion runs |
| `TOKEN_EXPIRY_HOURS` | `72` | JWT token lifetime |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## Roadmap

- [ ] Email digest delivery (SMTP)
- [ ] Web UI (React or simple HTML dashboard)
- [ ] AI-generated executive summaries per digest
- [ ] Webhook notifications (Slack, Discord, ntfy)
- [ ] Source reputation/trust scoring per feed
- [ ] User-submitted custom RSS feeds
- [ ] STIX/TAXII feed support

## Disclaimer

This service aggregates **publicly available** threat intelligence for **informational purposes only**.

- Subscribing to product-specific alerts **does not indicate or acknowledge** use of those products in your environment.
- This service is **not a substitute** for a formal threat intelligence program, incident response capability, or professional security advisory.
- The author makes no guarantees regarding the accuracy, completeness, or timeliness of the information provided.
- **Use at your own risk.** The author assumes no liability for decisions made based on this service's output.

See the [MIT License](LICENSE) for full terms.

## License

[MIT](LICENSE)
