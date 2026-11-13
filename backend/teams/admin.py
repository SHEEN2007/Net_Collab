from django.contrib import admin
from .models import Team, TeamMembership, Channel
admin.site.register(Team)
admin.site.register(TeamMembership)
admin.site.register(Channel)
