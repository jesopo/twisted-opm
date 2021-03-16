from collections import OrderedDict
from time        import monotonic
from typing      import Optional, Tuple

class Cache(object):
    def __init__(self,
            cache_size: int):
        self._cache_size = cache_size
        self._dict: OrderedDict[str, Tuple[str, float]] = OrderedDict()

    def __contains__(self, key: str) -> bool:
        if key in self._dict:
            value, expire = self._dict[key]
            return expire > monotonic()
        else:
            return False
    def __delitem__(self, key: str):
        del self._dict[key]
    def __bool__(self):
        return bool(self._dict)
    def clear(self):
        self._dict.clear()

    def get(self, key: str) -> Optional[str]:
        if key in self._dict:
            value, expire = self._dict[key]
            return value

        return None

    def set(self,
            key:   str,
            value: str,
            life:  int):

        now = monotonic()

        # prune expired entries
        # items are stored oldest, ..., newest
        for other_key, (value, expire) in list(self._dict.items()):
            if expire < now:
                del self._dict[other_key]
            else:
                break

        # if we've hit the max, pop the oldest
        if len(self._dict) == self._cache_size:
            self._dict.popitem(last=False)

        expire = now + life
        self._dict[key] = (value, expire)
        self._dict.move_to_end(key, last=True)
