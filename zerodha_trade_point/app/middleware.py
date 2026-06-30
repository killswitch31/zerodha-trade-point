from django.shortcuts import redirect
from django.urls import reverse


class LoginRequiredMiddleware:
    """Require authentication for app routes while allowing auth/static/admin endpoints."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path or ""
        login_path = reverse("login")
        logout_path = reverse("logout")

        is_public = (
            path.startswith("/static/")
            or path.startswith("/admin/")
            or path == login_path
            or path == logout_path
            or path.startswith("/kite/callback/")
        )

        if not is_public and not request.user.is_authenticated:
            return redirect("login")

        return self.get_response(request)
