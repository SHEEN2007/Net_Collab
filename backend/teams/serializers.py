
from rest_framework import serializers
from .models import Team, TeamMembership, Channel


class MemberSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)
    user_id = serializers.IntegerField(source="user.id", read_only=True)

    class Meta:
        model = TeamMembership
        fields = [
            "id",
            "user_id",
            "username",
            "email",
            "role",
            "joined_at"
        ]


class TeamSerializer(serializers.ModelSerializer):
    owner_name = serializers.CharField(source="owner.username", read_only=True)
    members = MemberSerializer(
        source="teammembership_set",
        many=True,
        read_only=True
    )

    class Meta:
        model = Team
        fields = [
            "id",
            "name",
            "description",
            "owner_name",
            "members",
            "created_at"
        ]
        read_only_fields = [
            "id",
            "owner_name",
            "members",
            "created_at"
        ]


class ChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Channel
        fields = [
            "id",
            "team",
            "name",
            "description",
            "created_by",
            "created_at"
        ]
        read_only_fields = [
            "id",
            "team",
            "created_by",
            "created_at"
        ]
