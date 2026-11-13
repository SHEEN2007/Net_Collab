from django.db import models
from django.contrib.auth.models import User

class Team(models.Model):
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_teams")
    members = models.ManyToManyField(User, through="TeamMembership", related_name="netcollab_teams")
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self): return self.name

class TeamMembership(models.Model):
    ROLE_CHOICES = [("owner", "Owner"), ("member", "Member")]
    team = models.ForeignKey(Team, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default="member")
    joined_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ("team", "user")

class Channel(models.Model):
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name="channels")
    name = models.CharField(max_length=80)
    description = models.CharField(max_length=255, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ("team", "name")
    def __str__(self): return f"{self.team.name} / {self.name}"
