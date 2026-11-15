from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/accounts/", include("accounts.urls")),
    path("api/teams/", include("teams.urls")),
    path("api/", include("projects.urls")),
    path("api/artifacts/", include("artifacts.urls")),
    path("api/accounts/login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/accounts/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
