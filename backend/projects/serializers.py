from rest_framework import serializers
from .models import Project, Task, Milestone

class TaskSerializer(serializers.ModelSerializer):
    assigned_username = serializers.CharField(source="assigned_to.username", read_only=True)
    class Meta:
        model = Task
        fields = "__all__"
        read_only_fields = ["id", "created_at"]

class MilestoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Milestone
        fields = "__all__"
        read_only_fields = ["id", "created_at"]

class ProjectSerializer(serializers.ModelSerializer):
    tasks = TaskSerializer(many=True, read_only=True)
    milestones = MilestoneSerializer(many=True, read_only=True)
    class Meta:
        model = Project
        fields = "__all__"
        read_only_fields = ["id", "created_by", "created_at"]
