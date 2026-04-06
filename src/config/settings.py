# config/settings.py (полный рабочий файл)
import os
import logging
from pathlib import Path
from dotenv import load_dotenv
from typing import Optional, List
from dataclasses import dataclass, field

load_dotenv()


@dataclass
class SecurityConfig:
    """Конфигурация безопасности"""
    max_requests_per_minute: int = 10
    request_timeout: int = 30
    max_message_length: int = 4000
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    blocked_domains: List[str] = field(default_factory=lambda: [
        'localhost', '127.0.0.1', '0.0.0.0', '::1',
        '169.254.169.254', 'metadata.google.internal', '169.254.169.253'
    ])


class Settings:
    """Управление настройками приложения"""

    def __init__(self):
        # Telegram
        self.BOT_TOKEN: str = os.getenv('BOT_TOKEN', '')

        # API Keys
        self.VIRUSTOTAL_API_KEY: str = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.ABUSEIPDB_API_KEY: str = os.getenv('ABUSEIPDB_API_KEY', '')
        self.GREYNOISE_API_KEY: str = os.getenv('GREYNOISE_API_KEY', '')
        self.HYBRID_ANALYSIS_API_KEY: str = os.getenv('HYBRID_ANALYSIS_API_KEY', '')

        # Security
        self.security = SecurityConfig(
            max_requests_per_minute=int(os.getenv('MAX_REQUESTS_PER_MINUTE', '10')),
            request_timeout=int(os.getenv('REQUEST_TIMEOUT', '30')),
            max_message_length=int(os.getenv('MAX_MESSAGE_LENGTH', '4000'))
        )

        # Paths
        self.BASE_DIR = Path(__file__).parent.parent
        self.DATA_DIR = self.BASE_DIR / 'data'
        self.LOGS_DIR = self.BASE_DIR / 'logs'

        # Create directories
        self.DATA_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)

        self._setup_logging()

    def _setup_logging(self):
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        log_level = os.getenv('LOG_LEVEL', 'INFO')

        logging.basicConfig(
            format=log_format,
            level=getattr(logging, log_level),
            handlers=[
                logging.FileHandler(self.LOGS_DIR / 'bot.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

    def validate(self) -> bool:
        if not self.BOT_TOKEN:
            logging.error("BOT_TOKEN not set in .env file")
            return False
        return True

    def get_api_key(self, service: str) -> Optional[str]:
        keys = {
            'virustotal': self.VIRUSTOTAL_API_KEY,
            'abuseipdb': self.ABUSEIPDB_API_KEY,
            'greynoise': self.GREYNOISE_API_KEY,
            'hybrid_analysis': self.HYBRID_ANALYSIS_API_KEY
        }
        key = keys.get(service.lower(), '')
        if not key or key.startswith('your_') or key == f'YOUR_{service.upper()}_API_KEY':
            return None
        return key


settings = Settings()
