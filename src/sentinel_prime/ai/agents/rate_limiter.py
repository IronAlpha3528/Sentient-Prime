import time
import threading
from collections import deque

class RateLimiter:
    """
    A thread-safe rate limiter that tracks API requests per key.
    Ensures that no single key exceeds the limit of 15 requests per minute.
    """
    def __init__(self, limit: int = 15, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests_per_key = {}
        self.lock = threading.Lock()

    def wait(self, api_key: str):
        """
        Blocks execution if the given API key has exceeded its rate limit.
        Releases execution once a slot frees up in the window.
        """
        if not api_key:
            return  # Can't rate limit an empty key

        with self.lock:
            if api_key not in self.requests_per_key:
                self.requests_per_key[api_key] = deque()
            
            queue = self.requests_per_key[api_key]
            
            while True:
                now = time.time()
                # Remove timestamps older than the window
                while queue and queue[0] <= now - self.window_seconds:
                    queue.popleft()
                
                # If we have capacity, record the request and proceed
                if len(queue) < self.limit:
                    queue.append(now)
                    return
                
                # Otherwise, calculate how long to wait until the oldest request expires
                wait_time = (queue[0] + self.window_seconds) - now
                if wait_time > 0:
                    # Release lock, sleep, and try again
                    self.lock.release()
                    time.sleep(wait_time)
                    self.lock.acquire()

# Global instance
rate_limiter = RateLimiter()
