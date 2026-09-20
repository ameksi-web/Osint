"""Защита от перегрузки: лимиты частоты поисков на пользователя.

Бот уходит в сеть десятками запросов на каждый поиск, поэтому важно не дать
одному пользователю (или самому себе по ошибке) залить источники и получить
блокировки. Лимиты мягкие и настраиваются через .env:

    TELEGRAM_SEARCH_COOLDOWN=8     # секунд между поисками одного пользователя
    TELEGRAM_MAX_PER_HOUR=40       # максимум поисков в час
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from ..config import get_settings


class RateLimiter:
    def __init__(self, cooldown: float | None = None, per_hour: int | None = None):
        settings = get_settings()
        self.cooldown = cooldown if cooldown is not None else settings.search_cooldown
        self.per_hour = per_hour if per_hour is not None else settings.max_searches_per_hour
        self._events: dict[int, deque[float]] = defaultdict(deque)

    def check(self, user_id: int, *, target: str = "") -> tuple[bool, str]:
        """Можно ли запускать поиск. Возвращает (можно, сообщение для пользователя)."""
        now = time.time()
        events = self._events[user_id]
        while events and now - events[0] > 3600:
            events.popleft()
        if events and now - events[-1] < self.cooldown:
            wait = self.cooldown - (now - events[-1])
            return False, f"⏳ Слишком часто: подождите {wait:.0f} с перед следующим поиском."
        if len(events) >= self.per_hour:
            return False, (f"⏳ Лимит: не больше {self.per_hour} поисков в час. "
                           f"Попробуйте позже или поднимите TELEGRAM_MAX_PER_HOUR в .env.")
        return True, ""

    def register(self, user_id: int) -> None:
        self._events[user_id].append(time.time())

    def cooldown_left(self, user_id: int) -> float:
        events = self._events[user_id]
        if not events:
            return 0.0
        return max(0.0, self.cooldown - (time.time() - events[-1]))

    def reset(self, user_id: int | None = None) -> None:
        if user_id is None:
            self._events.clear()
        else:
            self._events.pop(user_id, None)
