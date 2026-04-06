"""Rate limiter for API request throttling"""

import time
from typing import Dict, List
from config import settings


class RateLimiter:
    """Rate limiter to prevent abuse"""

    def __init__(self, max_requests: int = None, time_window: int = None):
        self.max_requests = max_requests or settings.security.max_requests_per_minute
        self.time_window = time_window or 60
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, user_id: str) -> bool:
        """
        Check if user is allowed to make a request

        Args:
            user_id: Telegram user ID

        Returns:
            bool: True if allowed
        """
        now = time.time()

        if user_id not in self.requests:
            self.requests[user_id] = []

        # Clean old requests
        self.requests[user_id] = [
            req_time for req_time in self.requests[user_id]
            if now - req_time < self.time_window
        ]

        # Check limit
        if len(self.requests[user_id]) >= self.max_requests:
            return False

        # Add new request
        self.requests[user_id].append(now)
        return True

    def get_remaining(self, user_id: str) -> int:
        """
        Get remaining requests for user

        Args:
            user_id: Telegram user ID

        Returns:
            int: Number of remaining requests
        """
        now = time.time()

        if user_id not in self.requests:
            return self.max_requests

        valid_requests = [
            req_time for req_time in self.requests[user_id]
            if now - req_time < self.time_window
        ]

        return max(0, self.max_requests - len(valid_requests))

    def reset(self, user_id: str):
        """Reset rate limit for user"""
        if user_id in self.requests:
            del self.requests[user_id]


# Global rate limiter instance
rate_limiter = RateLimiter()
