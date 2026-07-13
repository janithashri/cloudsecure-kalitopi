# CloudSecure — base settings (Phase 1)
# No external Prowler/Cartography APIs; boto3 only for test-connection.

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Load .env from project root so Celery/management commands get SECRET_KEY etc. (manage.py loads it for runserver)
_project_root = os.path.dirname(BASE_DIR)
_env_path = os.path.join(_project_root, ".env")
if os.path.exists(_env_path):
    from dotenv import load_dotenv
    load_dotenv(_env_path)


def _env(key: str, default: str = "") -> str:
    """Get env var; for POSTGRES_PASSWORD read from .env file so the exact value is used (avoids quote/encoding issues)."""
    if key == "POSTGRES_PASSWORD" and os.path.exists(_env_path):
        try:
            with open(_env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("POSTGRES_PASSWORD=") and not line.startswith("#"):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass
    return os.environ.get(key, default) or default


SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set")

DEBUG = False

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "django_celery_beat",
    "api",
    "accounts",
    "providers",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "cloudsecure.middleware.TenantMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "cloudsecure.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "cloudsecure.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _env("POSTGRES_DB") or "cloudsecure",
        "USER": _env("POSTGRES_USER") or "cloudsecure",
        "PASSWORD": _env("POSTGRES_PASSWORD"),
        "HOST": _env("POSTGRES_HOST") or "db",
        "PORT": _env("POSTGRES_PORT") or "5432",
        "OPTIONS": {"connect_timeout": 5},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# DRF
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

# CORS — frontend dev server
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Celery — Valkey (Redis-compatible)
VALKEY_URL = os.environ.get("VALKEY_URL", "redis://valkey:6379/0")
CELERY_BROKER_URL = VALKEY_URL
CELERY_RESULT_BACKEND = VALKEY_URL
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TASK_ROUTES = {
    "tasks.tasks.perform_inventory_pull_task": {"queue": "inventory"},
    "tasks.jobs.deep_scan.scan.run": {"queue": "deep_scan"},
}

# Neo4j (Phase 2 — delta inventory)
NEO4J_URI = os.environ.get("NEO4J_URI", "")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

# Neo4j — Deep Scan shared ingestion database
NEO4J_SHARED_URI = os.environ.get("NEO4J_SHARED_URI", NEO4J_URI)
NEO4J_SHARED_USER = os.environ.get("NEO4J_SHARED_USER", NEO4J_USER)
NEO4J_SHARED_PASSWORD = os.environ.get("NEO4J_SHARED_PASSWORD", NEO4J_PASSWORD)
NEO4J_SHARED_DATABASE = os.environ.get("NEO4J_SHARED_DATABASE", "neo4j")

# Neo4j — Deep Scan tenant isolation (optional, falls back to shared)
NEO4J_TENANT_URI_TEMPLATE = os.environ.get("NEO4J_TENANT_URI_TEMPLATE", "")
NEO4J_TENANT_USER = os.environ.get("NEO4J_TENANT_USER", NEO4J_SHARED_USER)
NEO4J_TENANT_PASSWORD = os.environ.get("NEO4J_TENANT_PASSWORD", NEO4J_SHARED_PASSWORD)

# Cartography — permission relationships config file
CARTOGRAPHY_PERMISSION_RELATIONSHIPS_FILE = os.environ.get(
    "CARTOGRAPHY_PERMISSION_RELATIONSHIPS_FILE", ""
)

# OPA Rule Engine
OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
RULES_DIR = os.path.join(BASE_DIR, "tasks", "jobs", "inventory", "rules")

# AWS Config-based drift signal (optional, non-breaking)
ENABLE_AWS_CONFIG_DRIFT = os.environ.get("ENABLE_AWS_CONFIG_DRIFT", "false").lower() in ("1", "true", "yes")
AWS_CONFIG_REGION = os.environ.get("AWS_CONFIG_REGION", os.environ.get("AWS_DEFAULT_REGION", "ap-south-1"))
AWS_CONFIG_INITIAL_LOOKBACK_MINUTES = int(os.environ.get("AWS_CONFIG_INITIAL_LOOKBACK_MINUTES", "180"))
