from django.contrib.auth.models import User
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Team, TeamMembership, Channel
from .serializers import TeamSerializer, MemberSerializer, ChannelSerializer

class TeamViewSet(viewsets.ModelViewSet):
    serializer_class = TeamSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Team.objects.filter(members=self.request.user).distinct().prefetch_related("teammembership_set__user")

    def perform_create(self, serializer):
        team = serializer.save(owner=self.request.user)
        TeamMembership.objects.create(team=team, user=self.request.user, role="owner")

    @action(detail=True, methods=["post"], url_path="members")
    def add_member(self, request, pk=None):
        team = self.get_object()
        if team.owner_id != request.user.id:
            return Response({"error": "Only the team owner can add members."}, status=403)
        username = request.data.get("username", "").strip()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found. They must register first."}, status=404)
        membership, created = TeamMembership.objects.get_or_create(team=team, user=user)
        if not created:
            return Response({"message": "User is already a member."}, status=200)
        return Response({"message": "Member added."}, status=201)

    @action(detail=True, methods=["get", "post"], url_path="channels")
    def channels(self, request, pk=None):
        team = self.get_object()
        if request.method == "GET":
            return Response(ChannelSerializer(team.channels.all(), many=True).data)
        serializer = ChannelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(team=team, created_by=request.user)
        return Response(serializer.data, status=201)

    @action(detail=True, methods=["delete"], url_path=r"members/(?P<user_id>[^/.]+)")
    def remove_member(self, request, pk=None, user_id=None):
        team = self.get_object()
        if team.owner_id != request.user.id:
            return Response({"error": "Only the team owner can remove members."}, status=403)
        if str(team.owner_id) == str(user_id):
            return Response({"error": "The owner cannot remove themselves."}, status=400)
        deleted, _ = TeamMembership.objects.filter(team=team, user_id=user_id).delete()
        return Response(status=204 if deleted else 404)
