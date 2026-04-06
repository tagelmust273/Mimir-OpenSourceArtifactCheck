
"""Secure HTTP client with SSRF protection"""

import aiohttp
import ipaddress
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from config import settings


class SecureHTTPClient:
    """HTTP client with SSRF protection and security hardening"""

    BLOCKED_SCHEMES = ['file', 'ftp', 'gopher', 'dict', 'ldap', 'data']

    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=settings.security.request_timeout)
        self._session: Optional[aiohttp.ClientSession] = None

    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers={
                    'User-Agent': 'OSINT-Bot/1.0 (Security Analysis Tool)',
                    'Accept': 'application/json',
                },
                raise_for_status=False
            )
        return self._session

    async def close(self):
        """Close HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()

    def _validate_url(self, url: str) -> bool:
        """
        Validate URL to prevent SSRF attacks

        Returns:
            bool: True if URL is safe
        """
        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme in self.BLOCKED_SCHEMES:
                return False

            # Check hostname
            hostname = parsed.hostname
            if not hostname:
                return False

            # Block internal hosts
            blocked_hosts = getattr(settings.security, 'blocked_domains', [
                'localhost', '127.0.0.1', '0.0.0.0', '::1',
                '169.254.169.254', 'metadata.google.internal', '169.254.169.253'
            ])
            if hostname in blocked_hosts:
                return False

            # Check for private IPs
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_multicast:
                    return False
            except ValueError:
                # Not an IP, continue with domain validation
                pass

            # Check port
            port = parsed.port
            allowed_ports = getattr(settings.security, 'allowed_ports', [80, 443, 8080, 8443])
            if port and port not in allowed_ports:
                return False

            return True

        except Exception:
            return False

    async def get_json(self, url: str, params: Optional[Dict] = None,
                       headers: Optional[Dict] = None) -> Optional[Dict]:
        """
        Perform safe GET request with JSON response

        Args:
            url: Request URL
            params: Query parameters
            headers: Request headers

        Returns:
            Optional[Dict]: JSON response or None
        """
        if not self._validate_url(url):
            return None

        session = await self.get_session()

        try:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
        except Exception:
            pass

        return None

    async def get_text(self, url: str, params: Optional[Dict] = None,
                       headers: Optional[Dict] = None) -> Optional[str]:
        """
        Perform safe GET request with text response

        Args:
            url: Request URL
            params: Query parameters
            headers: Request headers

        Returns:
            Optional[str]: Text response or None
        """
        if not self._validate_url(url):
            return None

        session = await self.get_session()

        try:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
        except Exception:
            pass

        return None


# Global HTTP client instance
http_client = SecureHTTPClient()
