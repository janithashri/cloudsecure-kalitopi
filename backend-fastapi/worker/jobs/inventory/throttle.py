import logging
import random
import time
from functools import wraps

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def stagger_accounts(accounts: list, batch_size: int = 10, delay_seconds: int = 180):
    for i in range(0, len(accounts), batch_size):
        batch = accounts[i : i + batch_size]
        yield batch
        if i + batch_size < len(accounts):
            jitter = random.uniform(0, 30)
            time.sleep(delay_seconds + jitter)


def with_backoff(max_attempts=5):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    if code in (
                        "ThrottlingException",
                        "RequestLimitExceeded",
                        "TooManyRequestsException",
                        "Throttling",
                    ):
                        wait = (2**attempt) + random.uniform(0, 1)
                        logger.warning(
                            f"Throttled on attempt {attempt + 1}, waiting {wait:.1f}s"
                        )
                        time.sleep(wait)
                        continue
                    raise
            raise RuntimeError(f"{fn.__name__} failed after {max_attempts} attempts")

        return wrapper

    return decorator

