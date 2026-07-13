#!/usr/bin/env python
import os
import sys

# Load .env so Django sees POSTGRES_HOST etc. (project root, then backend/ as fallback)
def load_env():
    from dotenv import load_dotenv
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(backend_dir)
    loaded = False
    for env_path in [os.path.join(project_root, ".env"), os.path.join(backend_dir, ".env")]:
        if os.path.exists(env_path):
            load_dotenv(env_path)
            print(f"[DEBUG] Loaded .env from {env_path}")
            loaded = True
            break
    if not loaded:
        print(f"[DEBUG] No .env found in project root or backend/")
    # Local dev: if POSTGRES_HOST still unset, use localhost (avoids hanging on "db")
    if not os.environ.get("POSTGRES_HOST"):
        os.environ.setdefault("POSTGRES_HOST", "localhost")
        print("[DEBUG] Set POSTGRES_HOST=localhost (was unset)")
    print(f"[DEBUG] POSTGRES_HOST={os.environ.get('POSTGRES_HOST')}")

if __name__ == "__main__":
    load_env()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cloudsecure.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("Django not installed.") from exc
    execute_from_command_line(sys.argv)
