from django.contrib import admin
from .models import Message, Notification


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    # body is ciphertext on purpose - admins cannot read chats from the DB.
    list_display = ("id", "sender", "channel", "recipient", "created_at")
    exclude = ("body",)


admin.site.register(Notification)
