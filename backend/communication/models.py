from django.conf import settings
from django.db import models


class Message(models.Model):
    """
    A chat message.  Exactly one of `channel` (group message in a team channel)
    or `recipient` (direct message) is set.

    `body` never holds plain text: it is base64(nonce || AES-256-GCM ciphertext),
    i.e. messages are encrypted at rest.  Use `.content` to read it.
    """
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages")
    channel = models.ForeignKey("teams.Channel", null=True, blank=True, on_delete=models.CASCADE, related_name="messages")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE, related_name="received_messages")
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]
        indexes = [
            models.Index(fields=["channel", "id"]),
            models.Index(fields=["sender", "recipient", "id"]),
        ]

    @property
    def kind(self):
        return "channel" if self.channel_id else "dm"

    @property
    def content(self):
        from .services import decrypt_body
        return decrypt_body(self.body)

    def __str__(self):
        return f"Message #{self.pk} ({self.kind})"


class Notification(models.Model):
    """One unread/read marker per recipient of a message."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="notifications")
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["user", "is_read"])]

    def __str__(self):
        return f"Notification #{self.pk} for {self.user_id}"
