
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from projects.models import Project


def artifact_upload_path(instance, filename):
    """Generate a safe, unique storage path for each version."""
    extension = filename.rsplit(".", 1)[-1] if "." in filename else "bin"

    return (
        f"artifacts/{instance.artifact.id}/"
        f"{uuid.uuid4().hex}.{extension[:20]}"
    )


class Artifact(models.Model):
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="artifacts"
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="uploaded_artifacts"
    )
    current_version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.project.name}"


class ArtifactVersion(models.Model):
    artifact = models.ForeignKey(
        Artifact,
        on_delete=models.CASCADE,
        related_name="versions"
    )
    version_number = models.PositiveIntegerField()
    file = models.FileField(upload_to=artifact_upload_path)
    original_filename = models.CharField(max_length=255)
    sha256_hash = models.CharField(max_length=64)
    file_size = models.PositiveBigIntegerField()
        # Encryption metadata
    is_encrypted = models.BooleanField(default=False)

    encryption_algorithm = models.CharField(
        max_length=32,
        default="none"
    )

    encryption_nonce = models.CharField(
        max_length=64,
        blank=True,
        default=""
    )

    encrypted_file_size = models.PositiveBigIntegerField(
        null=True,
        blank=True
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="artifact_versions"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-version_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["artifact", "version_number"],
                name="unique_artifact_version"
            )
        ]

    def __str__(self):
        return f"{self.artifact.name} - v{self.version_number}"


class ArtifactAccess(models.Model):
    PERMISSION_CHOICES = [
        ("view", "View"),
        ("download", "Download"),
    ]

    artifact = models.ForeignKey(
        Artifact,
        on_delete=models.CASCADE,
        related_name="access_grants"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="artifact_access"
    )
    permission = models.CharField(
        max_length=10,
        choices=PERMISSION_CHOICES,
        default="view"
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="granted_artifact_access"
    )
    granted_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["artifact", "user"],
                name="unique_artifact_user_access"
            )
        ]

    def __str__(self):
        return f"{self.user.username} - {self.artifact.name} ({self.permission})"

class ArtifactVersionKey(models.Model):
    """
    Stores a recipient-specific RSA-wrapped AES session key.

    The raw AES key is never stored in the database.
    """

    version = models.ForeignKey(
        ArtifactVersion,
        on_delete=models.CASCADE,
        related_name="recipient_keys"
    )

    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="artifact_version_keys"
    )

    wrapped_key = models.TextField()

    key_encryption_algorithm = models.CharField(
        max_length=32,
        default="RSA-OAEP-SHA256"
    )

    recipient_key_id = models.CharField(
        max_length=128,
        blank=True,
        default=""
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["version", "recipient"],
                name="unique_version_recipient_key"
            )
        ]

    def __str__(self):
        return (
            f"Version {self.version.version_number} - "
            f"{self.recipient.username}"
        )
