
from rest_framework import serializers

from .models import (
    Artifact,
    ArtifactVersion,
    ArtifactAccess,
    ArtifactVersionKey,
)


class ArtifactVersionSerializer(serializers.ModelSerializer):
    uploaded_by_name = serializers.CharField(
        source="uploaded_by.username",
        read_only=True
    )

    class Meta:
        model = ArtifactVersion
        fields = [
            "id",
            "version_number",
            "original_filename",
            "sha256_hash",
            "file_size",
            "uploaded_by",
            "uploaded_by_name",
            "is_encrypted",
            "encryption_algorithm",
            "encryption_nonce",
            "encrypted_file_size",
            "created_at",
        ]

        read_only_fields = fields


class ArtifactSerializer(serializers.ModelSerializer):
    uploaded_by_name = serializers.CharField(
        source="uploaded_by.username",
        read_only=True
    )

    versions = ArtifactVersionSerializer(
        many=True,
        read_only=True
    )

    class Meta:
        model = Artifact

        fields = [
            "id",
            "project",
            "name",
            "description",
            "uploaded_by",
            "uploaded_by_name",
            "current_version",
            "versions",
            "created_at",
            "updated_at",
        ]

        read_only_fields = [
            "id",
            "uploaded_by",
            "uploaded_by_name",
            "current_version",
            "versions",
            "created_at",
            "updated_at",
        ]


class ArtifactAccessSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        source="user.username",
        read_only=True
    )

    class Meta:
        model = ArtifactAccess

        fields = [
            "id",
            "user",
            "username",
            "permission",
            "granted_by",
            "granted_at",
        ]

        read_only_fields = [
            "id",
            "username",
            "granted_by",
            "granted_at",
        ]


class ArtifactVersionKeySerializer(serializers.ModelSerializer):
    recipient_username = serializers.CharField(
        source="recipient.username",
        read_only=True
    )

    class Meta:
        model = ArtifactVersionKey

        fields = [
            "id",
            "version",
            "recipient",
            "recipient_username",
            "wrapped_key",
            "key_encryption_algorithm",
            "recipient_key_id",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "created_at",
        ]
