# CloudSecure — local dev overrides
from .base import *

DEBUG = True

# See every request in runserver terminal (so we know if requests reach Django on Windows)
MIDDLEWARE = ["cloudsecure.middleware.DebugRequestMiddleware"] + list(MIDDLEWARE)

# Allow frontend from any origin in local dev (e.g. http://192.168.x.x:3000)
CORS_ALLOW_ALL_ORIGINS = True

# Debug logging — see request flow and DB in the terminal running runserver
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "debug": {
            "format": "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "debug",
        },
    },
    "loggers": {
        "django.request": {"level": "DEBUG", "handlers": ["console"]},
        "django.db.backends": {"level": "DEBUG", "handlers": ["console"]},
    },
}
