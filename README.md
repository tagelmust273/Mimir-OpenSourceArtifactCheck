# 🤖 Mimir - OpenSourceArtifactChecker Bot

![MimirHead](https://github.com/tagelmust273/Mimir---OpenSourceArtifactCheck/raw/main/mimirhead.jpg)

[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-blue.svg)](https://t.me/yourbot)

Telegram бот для автоматического анализа IP-адресов, доменов и хешей через OSINT-сервисы.

## ✨ Возможности

### 🔍 Анализ артефактов

| Тип | Сервисы |
|-----|---------|
| 🌐 **IP-адреса** | AbuseIPDB, GreyNoise, VirusTotal, Port Scanner, GeoLocation |
| 📡 **Домены** | WHOIS, DNS (A/MX/TXT/NS), SSL/TLS, URLScan.io, VirusTotal |
| 🔑 **Хеши** | VirusTotal, Hybrid Analysis |

### 📊 Дополнительные функции

- 📄 **PDF отчеты** с графиками и диаграммами
- 💾 **Экспорт данных** в CSV и JSON
- 📈 **Визуализация угроз** (круговые и столбчатые диаграммы)
- 🔗 **Графы связей** между артефактами
- 🗺️ **Геолокация** с картами OpenStreetMap
- 🔓 **Сканирование портов** (20+ популярных портов)

### 🔒 Безопасность

- ✅ Валидация всех входных данных
- ✅ Защита от SSRF атак
- ✅ Rate limiting (10 запросов/мин)
- ✅ Санитизация вывода
- ✅ Блокировка приватных IP
- ✅ Безопасный HTTP клиент

---

## 🚀 Быстрый старт

### Требования

- Docker (версия 20.10+)
- Docker Compose (версия 2.0+)
- Git

### Установка и запуск


# 1. Клонирование репозитория
git clone https://github.com/tagelmust273/Mimir-OpenSourceArtifactCheck.git

cd Mimir-OpenSourceArtifactCheck

# 2. Настройка переменных окружения
cp .env.example .env

# 3. Отредактируйте .env файл 
nano .env  

# 4. Запуск бота через Docker Compose
docker-compose -f docker/docker-compose.yml up -d

# 5. Просмотр логов для проверки работы
docker logs -f osint-bot
