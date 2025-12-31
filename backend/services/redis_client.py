import os
import redis

_client = None

def get_redis():
    global _client
    if _client is None:
        url = os.getenv("REDIS_URL", "redis://localhost:26380/0")
        _client = redis.Redis.from_url(url)
    return _client
