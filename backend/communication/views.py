from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from . import conf, crypto, services
from .models import Message, Notification

User = get_user_model()
DEFAULT_LIMIT, MAX_LIMIT = 50, 100


def _page(request, queryset):
    """Newest-first slice honouring ?before=<id>&limit=<n>, returned oldest-first."""
    try:
        limit = max(1, min(int(request.query_params.get("limit", DEFAULT_LIMIT)), MAX_LIMIT))
    except ValueError:
        limit = DEFAULT_LIMIT
    before = request.query_params.get("before")
    if before and before.isdigit():
        queryset = queryset.filter(id__lt=int(before))
    rows = list(queryset.select_related("sender").order_by("-id")[: limit + 1])
    has_more = len(rows) > limit
    rows = rows[:limit][::-1]
    return Response({"results": [services.serialize_message(m) for m in rows], "has_more": has_more})


class ServerInfoView(APIView):
    """Where to connect, plus the TCP server's RSA key fingerprint (for key pinning)."""

    def get(self, request):
        fingerprint = None
        if conf.KEY_PATH.exists():
            key = crypto.load_private_key_pem(conf.KEY_PATH.read_bytes())
            fingerprint = crypto.public_key_fingerprint(key.public_key())
        return Response({
            "tcp_host": conf.TCP_HOST, "tcp_port": conf.TCP_PORT,
            "ws_url": f"ws://{conf.WS_HOST}:{conf.WS_PORT}",
            "fingerprint": fingerprint,
            "max_message_chars": conf.MAX_MESSAGE_CHARS,
        })


class ContactsView(APIView):
    """Everyone who shares at least one team with the current user."""

    def get(self, request):
        users = User.objects.filter(id__in=services.teammate_ids(request.user.id)).select_related("profile").order_by("username")
        return Response([
            {"id": u.id, "username": u.username,
             "full_name": u.profile.full_name if hasattr(u, "profile") else u.username}
            for u in users
        ])


class ChannelMessagesView(APIView):
    def get(self, request, channel_id):
        channel = services.get_channel_for_user(request.user.id, channel_id)
        if channel is None:
            return Response({"error": "Channel not found or you are not a member."}, status=403)
        return _page(request, Message.objects.filter(channel=channel))


class DirectMessagesView(APIView):
    def get(self, request, user_id):
        me = request.user.id
        if user_id == me or not services.shares_team(me, user_id):
            return Response({"error": "You can only view conversations with your teammates."}, status=403)
        qs = Message.objects.filter(channel__isnull=True).filter(
            Q(sender_id=me, recipient_id=user_id) | Q(sender_id=user_id, recipient_id=me)
        )
        return _page(request, qs)


class NotificationsView(APIView):
    def get(self, request):
        qs = Notification.objects.filter(user=request.user).select_related("message__sender")
        if request.query_params.get("unread") in ("1", "true"):
            qs = qs.filter(is_read=False)
        return Response([services.serialize_notification(n) for n in qs[:100]])


class UnreadView(APIView):
    def get(self, request):
        return Response(services.unread_summary(request.user))


class MarkReadView(APIView):
    """POST {"channel_id": 3} | {"dm_user_id": 7} | {"all": true}"""

    def post(self, request):
        d = request.data
        updated = services.mark_read(
            request.user,
            channel_id=d.get("channel_id"),
            dm_user_id=d.get("dm_user_id"),
            everything=bool(d.get("all")),
        )
        return Response({"marked_read": updated})
