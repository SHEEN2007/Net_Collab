"""Business logic shared by the TCP server and the REST API."""
import base64
import hashlib
from functools import lru_cache

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Count
from teams.models import Channel, TeamMembership

from . import crypto
from .models import Message, Notification

User = get_user_model()


# ---- encryption at rest ----------------------------------------------------
@lru_cache(maxsize=1)
def _at_rest_key() -> bytes:
    return hashlib.sha256(b"netcollab-message-storage|" + settings.SECRET_KEY.encode()).digest()


def encrypt_body(text: str) -> str:
    return base64.b64encode(crypto.aes_encrypt_blob(_at_rest_key(), text.encode("utf-8"))).decode()


def decrypt_body(stored: str) -> str:
    try:
        return crypto.aes_decrypt_blob(_at_rest_key(), base64.b64decode(stored)).decode("utf-8")
    except Exception:
        return "[unreadable message]"


# ---- access control --------------------------------------------------------
def get_channel_for_user(user_id, channel_id):
    """The channel, but only if the user belongs to its team; otherwise None."""
    try:
        return Channel.objects.select_related("team").get(
            id=channel_id, team__teammembership__user_id=user_id
        )
    except Channel.DoesNotExist:
        return None


def shares_team(user_a, user_b) -> bool:
    return TeamMembership.objects.filter(
        user_id=user_a,
        team_id__in=TeamMembership.objects.filter(user_id=user_b).values("team_id"),
    ).exists()


def teammate_ids(user_id) -> set:
    mine = TeamMembership.objects.filter(user_id=user_id).values("team_id")
    return set(
        TeamMembership.objects.filter(team_id__in=mine)
        .exclude(user_id=user_id)
        .values_list("user_id", flat=True)
        .distinct()
    )


# ---- storing messages --------------------------------------------------------
def create_channel_message(sender, channel, content):
    """Store a channel message + a notification for every other team member."""
    msg = Message.objects.create(sender=sender, channel=channel, body=encrypt_body(content))
    recipients = list(
        TeamMembership.objects.filter(team_id=channel.team_id)
        .exclude(user_id=sender.id)
        .values_list("user_id", flat=True)
    )
    Notification.objects.bulk_create([Notification(user_id=uid, message=msg) for uid in recipients])
    return msg, recipients


def create_direct_message(sender, recipient_id, content):
    msg = Message.objects.create(sender=sender, recipient_id=recipient_id, body=encrypt_body(content))
    Notification.objects.create(user_id=recipient_id, message=msg)
    return msg


# ---- serialisation -----------------------------------------------------------
def serialize_message(msg) -> dict:
    return {
        "id": msg.id,
        "kind": msg.kind,
        "channel_id": msg.channel_id,
        "sender_id": msg.sender_id,
        "sender_username": msg.sender.username,
        "recipient_id": msg.recipient_id,
        "content": msg.content,
        "created_at": msg.created_at.isoformat(),
    }


def serialize_notification(n) -> dict:
    return {
        "id": n.id,
        "is_read": n.is_read,
        "created_at": n.created_at.isoformat(),
        "message": serialize_message(n.message),
    }


# ---- unread counters ---------------------------------------------------------
def unread_summary(user) -> dict:
    qs = Notification.objects.filter(user=user, is_read=False)
    channels = dict(
        qs.filter(message__channel__isnull=False)
        .values_list("message__channel_id").annotate(c=Count("id"))
    )
    dms = dict(
        qs.filter(message__channel__isnull=True)
        .values_list("message__sender_id").annotate(c=Count("id"))
    )
    return {
        "channels": {str(k): v for k, v in channels.items()},
        "dms": {str(k): v for k, v in dms.items()},
        "total": sum(channels.values()) + sum(dms.values()),
    }


def mark_read(user, *, channel_id=None, dm_user_id=None, everything=False) -> int:
    qs = Notification.objects.filter(user=user, is_read=False)
    if channel_id is not None:
        qs = qs.filter(message__channel_id=channel_id)
    elif dm_user_id is not None:
        qs = qs.filter(message__channel__isnull=True, message__sender_id=dm_user_id)
    elif not everything:
        return 0
    return qs.update(is_read=True)
