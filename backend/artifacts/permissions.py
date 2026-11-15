
from teams.models import TeamMembership
from .models import ArtifactAccess


def user_can_access_artifact(artifact, user, permission="view"):
    """
    Check artifact ownership, current team membership,
    and explicit sharing permissions.
    """

    # The uploader always has full access.
    if artifact.uploaded_by_id == user.id:
        return True

    # Shared users must still belong to the project's team.
    is_team_member = TeamMembership.objects.filter(
        team=artifact.project.team,
        user=user
    ).exists()

    if not is_team_member:
        return False

    grant = ArtifactAccess.objects.filter(
        artifact=artifact,
        user=user
    ).first()

    if not grant:
        return False

    if permission == "view":
        return grant.permission in ("view", "download")

    if permission == "download":
        return grant.permission == "download"

    return False


def user_can_upload_version(artifact, user):
    """Only the artifact uploader can create new versions."""
    return artifact.uploaded_by_id == user.id
