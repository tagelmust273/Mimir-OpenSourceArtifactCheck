# utils/rate_limiter.py (исправленный)
import time
from typing import Dict, List


class RateLimiter:
    """Rate limiter to prevent abuse"""

    def __init__(self, max_requests: int = 10, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, user_id: str) -> bool:
        now = time.time()

        if user_id not in self.requests:
            self.requests[user_id] = []

        self.requests[user_id] = [
            req_time for req_time in self.requests[user_id]
            if now - req_time < self.time_window
        ]

        if len(self.requests[user_id]) >= self.max_requests:
            return False

        self.requests[user_id].append(now)
        return True

    def get_remaining(self, user_id: str) -> int:
        now = time.time()

        if user_id not in self.requests:
            return self.max_requests

        valid_requests = [
            req_time for req_time in self.requests[user_id]
            if now - req_time < self.time_window
        ]

        return max(0, self.max_requests - len(valid_requests))

    def reset(self, user_id: str):
        if user_id in self.requests:
            del self.requests[user_id]


# Глобальный экземпляр будет создан в main.py после загрузки настроек
rate_limiter = None
