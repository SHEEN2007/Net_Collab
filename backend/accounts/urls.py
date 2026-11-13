from django.urls import path
from .views import RegisterView, ProfileView, WalletView
urlpatterns = [
    path("register/", RegisterView.as_view()),
    path("profile/", ProfileView.as_view()),
    path("wallet/", WalletView.as_view()),
]
