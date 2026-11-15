
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile


class RegisterSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ["username", "email", "password", "full_name"]

    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value

    def create(self, validated_data):
        full_name = validated_data.pop("full_name")
        password = validated_data.pop("password")
        user = User.objects.create_user(password=password, **validated_data)
        Profile.objects.create(user=user, full_name=full_name)
        return user


class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(required=False, allow_blank=True)

    class Meta:
        model = Profile
        fields = ["username", "email", "full_name", "wallet_address", "created_at"]
        read_only_fields = ["username", "wallet_address", "created_at"]

    def validate_email(self, value):
        user = self.instance.user
        if User.objects.filter(email__iexact=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def update(self, instance, validated_data):
        email = validated_data.pop("email", None)

        if email is not None:
            instance.user.email = email
            instance.user.save(update_fields=["email"])

        return super().update(instance, validated_data)

class PublicKeySerializer(serializers.Serializer):
    public_key = serializers.CharField()

    def validate_public_key(self, value):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        try:
            key = serialization.load_pem_public_key(value.encode("utf-8"))
        except (ValueError, TypeError):
            raise serializers.ValidationError(
                "Invalid PEM-encoded public key."
            )

        if not isinstance(key, rsa.RSAPublicKey):
            raise serializers.ValidationError(
                "Only RSA public keys are supported."
            )

        if key.key_size < 2048:
            raise serializers.ValidationError(
                "RSA key must be at least 2048 bits."
            )

        return value
