from collections import OrderedDict
from typing      import Optional

class Cache(object):
    def __init__(self, max: int=100):
        self._max = max
        self._dict: OrderedDict[str, str] = OrderedDict()

    def __contains__(self, key: str) -> bool:
        return key in self._dict

    def get(self, key: str) -> Optional[str]:
        if key in self._dict:
            self._dict.move_to_end(key)
            return self._dict[key]
        else:
            return None

    def set(self, key: str, value: str):
        self._dict[key] = value
        self._dict.move_to_end(key)
        if len(self._dict) > self._max:
            self._dict.popitem(last=False)
