
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth.models import User
from .models import Profile
from .serializers import RegisterSerializer, ProfileSerializer
from django.utils import timezone
from cryptography.hazmat.primitives import serialization
from .serializers import PublicKeySerializer
from cryptography.hazmat.primitives import hashes
import re
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

        wallet_address = request.data.get("wallet_address", "").strip()

        if not wallet_address:
            return Response(
                {"error": "Wallet address is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", wallet_address):
            return Response(
                {"error": "Invalid Ethereum wallet address."},
                status=status.HTTP_400_BAD_REQUEST
            )

        profile.wallet_address = wallet_address
        profile.save(update_fields=["wallet_address"])

        return Response(
            {
                "message": "Wallet connected successfully.",
                "wallet_address": profile.wallet_address
            },
            status=status.HTTP_200_OK
        )

# RSA Public Key Registration
class PublicKeyView(generics.GenericAPIView):
    serializer_class = PublicKeySerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        username = request.query_params.get("username", "").strip()

        if not username:
            return Response(
                {"error": "Username is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        profile = Profile.objects.filter(user=user).first()

        if not profile or not profile.public_key:
            return Response(
                {"error": "This user has not registered a public key."},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response({
            "username": user.username,
            "public_key": profile.public_key,
            "key_fingerprint": profile.key_fingerprint,
            "key_created_at": profile.key_created_at
        }, status=status.HTTP_200_OK)
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        public_key_pem = serializer.validated_data["public_key"]

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )

        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        fingerprint = hashes.Hash(hashes.SHA256())
        fingerprint.update(public_key_der)
        fingerprint = fingerprint.finalize().hex()

        profile, created = Profile.objects.get_or_create(
            user=request.user,
            defaults={"full_name": request.user.username}
        )

        profile.public_key = public_key_pem
        profile.key_fingerprint = fingerprint
        profile.key_created_at = timezone.now()

        profile.save(update_fields=[
            "public_key",
            "key_fingerprint",
            "key_created_at"
        ])

        return Response({
            "message": "RSA public key registered successfully.",
            "fingerprint": fingerprint,
            "key_created_at": profile.key_created_at
        }, status=status.HTTP_200_OK)
