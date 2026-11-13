from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from teams.models import TeamMembership
from .models import Project, Task, Milestone
from .serializers import ProjectSerializer, TaskSerializer, MilestoneSerializer

class ProjectViewSet(viewsets.ModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Project.objects.filter(team__members=self.request.user).distinct().prefetch_related("tasks", "milestones")
    def perform_create(self, serializer):
        team = serializer.validated_data["team"]
        if not TeamMembership.objects.filter(team=team, user=self.request.user).exists():
            raise PermissionDenied("You must belong to this team.")
        serializer.save(created_by=self.request.user)

class TaskViewSet(viewsets.ModelViewSet):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Task.objects.filter(project__team__members=self.request.user).distinct()
    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        if not TeamMembership.objects.filter(team=project.team, user=self.request.user).exists():
            raise PermissionDenied("You must belong to this project's team.")
        assignee = serializer.validated_data.get("assigned_to")
        if assignee and not TeamMembership.objects.filter(team=project.team, user=assignee).exists():
            raise PermissionDenied("Assignee must belong to the project team.")
        serializer.save()

class MilestoneViewSet(viewsets.ModelViewSet):
    serializer_class = MilestoneSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Milestone.objects.filter(project__team__members=self.request.user).distinct()
    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        if not TeamMembership.objects.filter(team=project.team, user=self.request.user).exists():
            raise PermissionDenied("You must belong to this project's team.")
        serializer.save()
