
from rest_framework import generics, permissions, status
from rest_framework.response import Response

from .models import Profile
from .serializers import RegisterSerializer, ProfileSerializer


# User Registration
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


# User Profile
class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        profile, created = Profile.objects.get_or_create(
            user=self.request.user,
            defaults={
                "full_name": self.request.user.username
            }
        )
        return profile


# MetaMask Wallet Connection
class WalletView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        profile, created = Profile.objects.get_or_create(
            user=request.user,
            defaults={
                "full_name": request.user.username
            }
        )

        wallet_address = request.data.get("wallet_address")

        if not wallet_address:
            return Response(
                {"error": "Wallet address is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        profile.wallet_address = wallet_address
        profile.save()

        return Response(
            {
                "message": "Wallet connected successfully.",
                "wallet_address": profile.wallet_address
            },
            status=status.HTTP_200_OK
        )
