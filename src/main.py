# main.py (полный рабочий файл)
#!/usr/bin/env python3
"""OSINT Artifact Analyzer Bot"""

import sys
import asyncio
import logging
from signal import SIGINT, SIGTERM

from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler

from config import settings
from handlers import commands, messages, callbacks
from security.http_client import http_client
from utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

# Инициализация rate_limiter с настройками
from utils.rate_limiter import rate_limiter as _rl
_rl = RateLimiter(max_requests=settings.security.max_requests_per_minute)


async def shutdown_handler(application: Application):
    """Graceful shutdown handler"""
    logger.info("Shutting down gracefully...")
    await http_client.close()
    await application.stop()
    await application.shutdown()


def main():
    """Main entry point"""
    if not settings.validate():
        logger.error("Invalid configuration. Check .env file")
        sys.exit(1)

    logger.info(f"Starting OSINT Artifact Analyzer Bot v1.0.0")
    logger.info(f"Data directory: {settings.DATA_DIR}")
    logger.info(f"Logs directory: {settings.LOGS_DIR}")

    application = Application.builder().token(settings.BOT_TOKEN).build()

    # Add handlers
    application.add_handler(CommandHandler("start", commands.start))
    application.add_handler(CommandHandler("help", commands.help_command))
    application.add_handler(CommandHandler("about", commands.about))
    application.add_handler(CommandHandler("stats", commands.stats))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, messages.handle_message))
    application.add_handler(CallbackQueryHandler(callbacks.handle_callback))

    # Setup shutdown
    loop = asyncio.get_event_loop()
    for sig in (SIGINT, SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown_handler(application)))

    logger.info("Bot started successfully!")
    application.run_polling()


if __name__ == "__main__":
    main()
