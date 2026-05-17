"""Command handlers for /start, /help, /about, /stats"""

from telegram import Update
from telegram.ext import ContextTypes
from utils.rate_limiter import RateLimiter
from config import settings

rate_limiter = RateLimiter(max_requests=settings.security.max_requests_per_minute)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    text = """
🔐 *Mimir - OSINT Artifact Analyzer Bot*

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
• 10 запросов в минуту (из-за ограничений сервисов)
• Только публичные IP
• Максимум 4000 символов в ответе

*После анализа доступны:*
• 📊 PDF отчет
• 📈 диаграмма угроз
• 💾 экспорт CSV/JSON

*Примеры:*
8.8.8.8
google.com
5d41402abc4b2a76b9719d911017c592
"""
    await update.message.reply_text(text, parse_mode='Markdown')


async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /about command"""
    text = """
ℹ️ *О боте*

*Mimir - OSINT Artifact Analyzer Bot v1.0*

Инструмент для анализа подозрительных артефактов с использованием OSINT-сервисов..

*Технологии:*
• Python 3.11
• python-telegram-bot 20.6
• aiohttp (асинхронные запросы)
• Matplotlib + NetworkX (визуализация)
• ReportLab (PDF отчеты)
• Docker (контейнеризация)

*Безопасность:*
• Валидация входных данных
• Защита от SSRF атак
• Rate limiting
• Санитизация вывода
• Блокировка приватных IP

*Разработчик:* Tamirlan Tarchokov ( a.k.a tagelmust, holydiver, goldwinchester )
."""
    await update.message.reply_text(text, parse_mode='Markdown')


async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /stats command"""
    from utils.rate_limiter import RateLimiter
    from config import settings 

    my_limiter = RateLimiter(max_requests=settings.security.max_requests_per_minute)

    user_id = str(update.effective_user.id)
    remaining = my_limiter.get_remaining(user_id)
    total_analyzed = context.user_data.get('total_analyzed', 0)

    text = f"""
📊 *Статистика*

Ваш лимит: 10 запросов в минуту
Осталось запросов: {remaining}

Всего обработано артефактов: {total_analyzed}
"""
    await update.message.reply_text(text, parse_mode='Markdown')

