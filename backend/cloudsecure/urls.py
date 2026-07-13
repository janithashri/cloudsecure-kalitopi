from django.contrib import admin
from django.http import JsonResponse
from django.urls import path, include
from django.db import connection

def health_view(request):
    """No DB, no auth — use this to confirm the server responds."""
    return JsonResponse({"status": "ok", "message": "Server is responding (no DB check)"})

def debug_db_view(request):
    """Test DB connection — will timeout or error if DB unreachable."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return JsonResponse({
            "status": "ok",
            "db": "connected",
            "host": connection.settings_dict.get("HOST"),
        })
    except Exception as e:
        return JsonResponse(
            {"status": "error", "db": str(e)},
            status=500,
        )

urlpatterns = [
    path("health/", health_view),
    path("debug-db/", debug_db_view),
    path("admin/", admin.site.urls),
    path("api/auth/", include("api.v1.urls")),
    path("api/v1/", include("providers.v1.urls")),
    path("api/v1/", include("api.v1.deep_scan_urls")),
]
