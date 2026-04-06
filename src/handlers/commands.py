"""Command handlers for /start, /help, /about, /stats"""

from telegram import Update
from telegram.ext import ContextTypes


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    text = """
🔐 *OSINT Artifact Analyzer Bot*

Анализ IP-адресов, доменов и хешей через OSINT-сервисы.

*Поддерживается:*
• 🌐 IP-адреса (только публичные)
• 📡 Доменные имена
• 🔑 Хеши (MD5, SHA1, SHA256)

*Доступные сервисы:*
• VirusTotal • AbuseIPDB • GreyNoise
• URLScan.io • WHOIS • DNS • SSL
• Port Scanner • GeoLocation

*Команды:*
/help - справка
/about - о боте
/stats - статистика

*Просто отправьте артефакт для анализа!*
"""
    await update.message.reply_text(text, parse_mode='Markdown')


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    text = """
📖 *Справка*

*Форматы артефактов:*
• IP: `8.8.8.8` или `1.1.1.1`
• Домен: `google.com` или `github.com`
• MD5: `5d41402abc4b2a76b9719d911017c592`
• SHA1: `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`
• SHA256: `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`

*Ограничения:*
• 10 запросов в минуту
• Только публичные IP
• Максимум 4000 символов в ответе

*После анализа доступны:*
• 📊 PDF отчет
• 📈 диаграмма угроз
• 💾 экспорт CSV/JSON

*Примеры:*
