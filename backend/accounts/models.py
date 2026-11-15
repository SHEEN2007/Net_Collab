
from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile"
    )
    full_name = models.CharField(max_length=100)
    wallet_address = models.CharField(max_length=42, blank=True, null=True)

    # RSA public key used for secure artifact sharing
    public_key = models.TextField(blank=True, default="")
    key_fingerprint = models.CharField(max_length=64, blank=True, default="")
    key_created_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username
