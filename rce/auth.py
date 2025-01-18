from redis.asyncio import Redis
from os import getenv as ev
from typing import Optional

rh = ev("REDIS_HOST", "localhost")
rp = int(ev("REDIS_PORT", "6379"))
rc = Redis(host=rh, port=rp)