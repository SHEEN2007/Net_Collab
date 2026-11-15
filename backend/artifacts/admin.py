
from django.contrib import admin

from .models import (
    Artifact,
    ArtifactVersion,
    ArtifactAccess,
    ArtifactVersionKey,
)


class ArtifactVersionInline(admin.TabularInline):
    model = ArtifactVersion
    extra = 0

    readonly_fields = (
        "sha256_hash",
        "file_size",
        "is_encrypted",
        "encryption_algorithm",
        "encrypted_file_size",
        "created_at",
    )


@admin.register(Artifact)
class ArtifactAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "project",
        "uploaded_by",
        "current_version",
        "created_at",
    )

    search_fields = ("name", "project__name")
    inlines = [ArtifactVersionInline]


@admin.register(ArtifactVersion)
class ArtifactVersionAdmin(admin.ModelAdmin):
    list_display = (
        "artifact",
        "version_number",
        "original_filename",
        "is_encrypted",
        "encryption_algorithm",
        "sha256_hash",
        "file_size",
        "created_at",
    )

    readonly_fields = (
        "sha256_hash",
        "file_size",
        "is_encrypted",
        "encryption_algorithm",
        "encryption_nonce",
        "encrypted_file_size",
        "created_at",
    )


@admin.register(ArtifactAccess)
class ArtifactAccessAdmin(admin.ModelAdmin):
    list_display = (
        "artifact",
        "user",
        "permission",
        "granted_by",
        "granted_at",
    )


@admin.register(ArtifactVersionKey)
class ArtifactVersionKeyAdmin(admin.ModelAdmin):
    list_display = (
        "version",
        "recipient",
        "key_encryption_algorithm",
        "recipient_key_id",
        "created_at",
    )

    readonly_fields = ("created_at",)
