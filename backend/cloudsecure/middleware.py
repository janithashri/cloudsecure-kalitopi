import sys


class DebugRequestMiddleware:
    """Log every request start so we can see if requests reach Django (e.g. on Windows)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(f"[REQUEST] {request.method} {request.path}", flush=True)
        return self.get_response(request)


class TenantMiddleware:
    """Set request.tenant from authenticated user's profile for API views."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.tenant = None
        if request.user and request.user.is_authenticated and hasattr(request.user, "profile"):
            request.tenant = getattr(request.user.profile, "tenant", None)
        return self.get_response(request)
