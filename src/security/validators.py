"""Input validation utilities"""

import re
import ipaddress
from typing import Tuple, Optional


class InputValidator:
    """Validates input artifacts (IPs, domains, hashes)"""

    # Domain pattern
    DOMAIN_PATTERN = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.'
        r'[A-Za-z]{2,}$'
    )

    # IP pattern
    IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

    # Hash patterns
    HASH_PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
    }

    # Private IP ranges
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
    ]

    @classmethod
    def validate_ip(cls, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Validate IP address (public only)

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        if not cls.IP_PATTERN.match(ip):
            return False, "Invalid IP format"

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check for private IP
            for private_range in cls.PRIVATE_IP_RANGES:
                if ip_obj in private_range:
                    return False, "Private IP addresses are not allowed"

            # Check for multicast
            if ip_obj.is_multicast:
                return False, "Multicast IP addresses are not allowed"

            # Check for unspecified
            if ip_obj.is_unspecified:
                return False, "Unspecified IP address is not allowed"

            # Check for loopback
            if ip_obj.is_loopback:
                return False, "Loopback IP addresses are not allowed"

            return True, None

        except ValueError:
            return False, "Invalid IP address"

    @classmethod
    def validate_domain(cls, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Validate domain name

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        domain = domain.lower().strip()

        if len(domain) > 253:
            return False, "Domain name is too long"

        if not cls.DOMAIN_PATTERN.match(domain):
            return False, "Invalid domain name format"

        # Check if domain is actually an IP
        try:
            ipaddress.ip_address(domain)
            return False, "Domain name cannot be an IP address"
        except ValueError:
            pass

        # Block localhost variants
        blocked = ['localhost', 'local', 'loopback']
        if domain in blocked or domain.endswith('.localhost'):
            return False, "Localhost domains are not allowed"

        return True, None

    @classmethod
    def validate_hash(cls, hash_value: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate hash value

        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (is_valid, error_message, hash_type)
        """
        hash_value = hash_value.lower().strip()

        for hash_type, pattern in cls.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                return True, None, hash_type

        return False, "Invalid hash format. Supported: MD5, SHA1, SHA256", None

    @classmethod
    def validate_artifact(cls, artifact: str) -> Tuple[str, str, Optional[str]]:
        """
        Detect and validate artifact type

        Returns:
            Tuple[str, str, Optional[str]]: (type, value, error_message)
        """
        artifact = artifact.strip()

        if not artifact:
            return "unknown", "", "Empty input"

        if len(artifact) > 2048:
            return "unknown", "", "Input too long"

        # Check IP
        is_valid, error = cls.validate_ip(artifact)
        if is_valid:
            return "ip", artifact, None

        # Check domain
        is_valid, error = cls.validate_domain(artifact)
        if is_valid:
            return "domain", artifact, None

        # Check hash
        is_valid, error, hash_type = cls.validate_hash(artifact)
        if is_valid:
            return "hash", artifact, None

        return "unknown", artifact, error or "Unknown artifact type"
