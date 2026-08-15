"""
fakeredis_client - minimal stand-in for redis.Redis, covering only the
commands logmon actually uses: lpush/ltrim/lrange/lindex/keys, plus the
pipeline() context that batches lpush+ltrim.

Not a general Redis emulator -- e.g. no expiry, no pattern globs beyond the
literal "prefix*:suffix" shape logmon's own key names use.
"""
from __future__ import annotations

import fnmatch


class _FakePipeline:
    def __init__(self, client: "FakeRedis"):
        self._client = client
        self._ops: list[tuple[str, tuple]] = []

    def lpush(self, key, value):
        self._ops.append(("lpush", (key, value)))
        return self

    def ltrim(self, key, start, end):
        self._ops.append(("ltrim", (key, start, end)))
        return self

    def execute(self):
        for name, args in self._ops:
            getattr(self._client, name)(*args)
        self._ops = []


class FakeRedis:
    """In-memory list store, newest-first (matching LPUSH semantics)."""

    def __init__(self):
        self._lists: dict[str, list[str]] = {}

    def lpush(self, key, value):
        self._lists.setdefault(key, []).insert(0, value)

    def ltrim(self, key, start, end):
        lst = self._lists.get(key, [])
        # redis LTRIM end is inclusive
        self._lists[key] = lst[start: end + 1] if end >= 0 else lst[start:]

    def lrange(self, key, start, end):
        lst = self._lists.get(key, [])
        if end == -1:
            return lst[start:]
        return lst[start: end + 1]

    def lindex(self, key, index):
        lst = self._lists.get(key, [])
        try:
            return lst[index]
        except IndexError:
            return None

    def keys(self, pattern):
        return [k for k in self._lists if fnmatch.fnmatchcase(k, pattern)]

    def pipeline(self):
        return _FakePipeline(self)
