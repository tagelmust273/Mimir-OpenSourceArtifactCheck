# 🤖 OSINT Artifact Analyzer Bot

[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-blue.svg)](https://t.me/yourbot)

Telegram бот для автоматического анализа IP-адресов, доменов и хешей через OSINT-сервисы.

## ✨ Возможности

| Тип | Сервисы |
|-----|---------|
| 🌐 IP | AbuseIPDB, GreyNoise, VirusTotal, Port Scanner, GeoLocation |
| 📡 Домен | WHOIS, DNS, SSL, URLScan.io, VirusTotal |
| 🔑 Хеш | VirusTotal, Hybrid Analysis |

### Дополнительно
- 📊 PDF отчеты с графиками
- 💾 Экспорт в CSV/JSON
- 📈 Визуализация угроз
- 🔗 Графы связей
- 🗺️ Геолокация на карте

## 🚀 Быстрый старт

### Локальный запуск

# Клонирование
git clone https://github.com/yourusername/osint-bot.git
cd osint-bot

# Настройка
cp .env.example .env
# Отредактируйте .env (добавьте BOT_TOKEN)

# Установка
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Запуск
python src/main.py
