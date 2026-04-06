# OSINT Artifact Analyzer Bot

Telegram бот для анализа IP-адресов, доменов и хешей с использованием OSINT-сервисов.

## Features

- ✅ IP address analysis (AbuseIPDB, GreyNoise, VirusTotal)
- ✅ Domain analysis (WHOIS, DNS, SSL, URLScan, VirusTotal)
- ✅ Hash analysis (VirusTotal, Hybrid Analysis)
- ✅ Port scanning
- ✅ GeoLocation with maps
- ✅ PDF reports generation
- ✅ CSV/JSON export
- ✅ Threat visualization charts
- ✅ Rate limiting & security

## Installation

1. Clone repository
2. Copy `.env.example` to `.env` and fill in your tokens
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `python main.py`

## Deployment

Use systemd service for production:

```bash
sudo cp osintbot.service /etc/systemd/system/
sudo systemctl enable osintbot
sudo systemctl start osintbot
