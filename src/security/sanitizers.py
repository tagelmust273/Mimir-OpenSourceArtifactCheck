"""Output sanitization utilities"""

import html
from typing import Any, Dict, List


class OutputSanitizer:
    """Sanitizes output to prevent injection attacks"""

    # Telegram Markdown special characters
    MARKDOWN_SPECIAL = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']

    @classmethod
    def sanitize_markdown(cls, text: str) -> str:
        """Escape Telegram Markdown special characters"""
        if not text:
            return ""

        for char in cls.MARKDOWN_SPECIAL:
            text = text.replace(char, f'\\{char}')
        return text

    @classmethod
    def sanitize_html(cls, text: str) -> str:
        """Escape HTML special characters"""
        return html.escape(str(text))

    @classmethod
    def truncate(cls, text: str, max_length: int = 4000) -> str:
        """Truncate text to safe length"""
        if not text:
            return ""

        if len(text) <= max_length:
            return text

        truncated = text[:max_length - 3]
        last_space = truncated.rfind(' ')
        if last_space > 0:
            truncated = truncated[:last_space]

        return truncated + "..."

    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any], max_depth: int = 3) -> Dict[str, Any]:
        """Recursively sanitize dictionary values"""
        if max_depth <= 0:
            return {"error": "Maximum depth exceeded"}

        result = {}
        for key, value in data.items():
            safe_key = cls.sanitize_html(str(key))

            if isinstance(value, dict):
                result[safe_key] = cls.sanitize_dict(value, max_depth - 1)
            elif isinstance(value, list):
                result[safe_key] = cls.sanitize_list(value, max_depth - 1)
            elif isinstance(value, str):
                result[safe_key] = cls.sanitize_html(value)
            elif isinstance(value, (int, float, bool)):
                result[safe_key] = value
            else:
                result[safe_key] = cls.sanitize_html(str(value))

        return result

    @classmethod
    def sanitize_list(cls, lst: List[Any], max_depth: int = 3) -> List[Any]:
        """Recursively sanitize list items"""
        if max_depth <= 0:
            return ["Maximum depth exceeded"]

        result = []
        for item in lst:
            if isinstance(item, dict):
                result.append(cls.sanitize_dict(item, max_depth - 1))
            elif isinstance(item, list):
                result.append(cls.sanitize_list(item, max_depth - 1))
            elif isinstance(item, str):
                result.append(cls.sanitize_html(item))
            elif isinstance(item, (int, float, bool)):
                result.append(item)
            else:
                result.append(cls.sanitize_html(str(item)))

        return result

    @classmethod
    def safe_format(cls, text: str, **kwargs) -> str:
        """Safely format string with escaped values"""
        safe_kwargs = {k: cls.sanitize_html(str(v)) for k, v in kwargs.items()}
        try:
            return text.format(**safe_kwargs)
        except (KeyError, ValueError):
            return text
