#!/usr/bin/env python3
"""
OSINT Artifact Analyzer Bot
Telegram bot for analyzing IPs, domains, and hashes using OSINT services
"""

import sys
import logging
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler

from config import settings
from handlers import commands, messages, callbacks
from security.http_client import http_client

logger = logging.getLogger(__name__)


async def shutdown():
    """Graceful shutdown"""
    logger.info("Shutting down...")
    await http_client.close()


def main():
    """Main entry point"""
    if not settings.validate():
        logger.error("Invalid configuration. Check .env file")
        sys.exit(1)

    logger.info("Starting OSINT Artifact Analyzer Bot...")

    # Create application
    application = Application.builder().token(settings.BOT_TOKEN).build()

    # Add handlers
    application.add_handler(CommandHandler("start", commands.start))
    application.add_handler(CommandHandler("help", commands.help_command))
    application.add_handler(CommandHandler("about", commands.about))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, messages.handle_message))
    application.add_handler(CallbackQueryHandler(callbacks.handle_callback))

    # Setup shutdown
    application.add_handler(shutdown)

    # Run bot
    logger.info("Bot started!")
    application.run_polling()


if __name__ == "__main__":
    main()
