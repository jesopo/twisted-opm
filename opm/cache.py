from collections import OrderedDict
from time        import monotonic
from typing      import Optional, Tuple

class Cache(object):
    def __init__(self,
            cache_time: int,
            cache_size: int):
        self._cache_time = cache_time
        self._cache_size = cache_size
        self._dict: OrderedDict[str, Tuple[str, float]] = OrderedDict()

    def __contains__(self, key: str) -> bool:
        if key in self._dict:
            value, expire = self._dict[key]
            return expire > monotonic()
        else:
            return False

    def get(self, key: str) -> Optional[str]:
        if key in self._dict:
            value, expire = self._dict[key]
            return value

        return None

    def set(self, key: str, value: str):
        now = monotonic()

        # prune expired entries
        # items are stored newest, ..., oldest so iter backwards
        for key, (value, time) in reversed(list(self._dict.items())):
            if time < now:
                del self._dict[key]
            else:
                break

        # if we've hit the max, pop the oldest
        if len(self._dict) == self._cache_size:
            self._dict.popitem(last=True)

        expire = now + self._cache_time
        self._dict[key] = (value, expire)
