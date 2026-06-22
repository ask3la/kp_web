import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Generator


@dataclass
class _Session:
    q: queue.Queue = field(default_factory=queue.Queue)
    created_at: float = field(default_factory=time.time)
    done: bool = False


class DownloadProxyBroker:
    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def open(self, token: str) -> None:
        with self._lock:
            self._sessions[token] = _Session()

    def _get(self, token: str) -> _Session | None:
        with self._lock:
            return self._sessions.get(token)

    def push(self, token: str, chunk: bytes) -> bool:
        s = self._get(token)
        if not s or s.done:
            return False
        s.q.put(chunk)
        return True

    def fail(self, token: str, message: str) -> None:
        s = self._get(token)
        if not s or s.done:
            return
        s.done = True
        s.q.put(("error", message))
        s.q.put(None)

    def complete(self, token: str) -> None:
        s = self._get(token)
        if not s or s.done:
            return
        s.done = True
        s.q.put(None)

    def stream(self, token: str, idle_timeout_sec: int = 120) -> Generator[bytes, None, None]:
        s = self._get(token)
        if not s:
            return
        while True:
            try:
                item = s.q.get(timeout=idle_timeout_sec)
            except queue.Empty:
                break
            if item is None:
                break
            if isinstance(item, tuple) and item and item[0] == "error":
                break
            if isinstance(item, (bytes, bytearray)):
                yield bytes(item)
        with self._lock:
            self._sessions.pop(token, None)


broker = DownloadProxyBroker()

