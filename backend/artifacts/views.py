import os

from django.contrib.auth.models import User
from django.db import models, transaction
from django.http import FileResponse
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.exceptions import PermissionDenied

from django.db.models import Q

from projects.models import Project
from teams.models import TeamMembership

from .models import Artifact, ArtifactVersion, ArtifactAccess
from .serializers import (
    ArtifactSerializer,
    ArtifactVersionSerializer,
    ArtifactAccessSerializer,
)
from .services.hashing import calculate_sha256, verify_artifact_version
from .permissions import (
    user_can_access_artifact,
    user_can_upload_version,
)

def get_accessible_artifact(artifact_id, user, permission="view"):
    artifact = get_object_or_404(
        Artifact.objects.select_related(
            "project__team",
            "uploaded_by"
        ),
        pk=artifact_id
    )

    if not user_can_access_artifact(artifact, user, permission):
        raise PermissionDenied(
            "You do not have permission to access this artifact."
        )

    return artifact

class ArtifactListUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    
    def get(self, request):
        """List only artifacts the user is allowed to view."""

        artifacts = (
            Artifact.objects
            .filter(
                Q(uploaded_by=request.user)
                | Q(
                    access_grants__user=request.user,
                    project__team__members=request.user
                )
            )
            .distinct()
            .select_related("project", "uploaded_by")
            .prefetch_related("versions")
            .order_by("-created_at")
        )

        serializer = ArtifactSerializer(artifacts, many=True)
        return Response(serializer.data)


    def post(self, request):
        """Upload a new artifact and create its first version."""

        project_id = request.data.get("project")
        uploaded_file = request.FILES.get("file")

        if not project_id:
            return Response(
                {"error": "Project ID is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not uploaded_file:
            return Response(
                {"error": "Please select a file to upload."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Basic upload-size limit: 100 MB.
        max_size = 100 * 1024 * 1024

        if uploaded_file.size > max_size:
            return Response(
                {"error": "File size cannot exceed 100 MB."},
                status=status.HTTP_400_BAD_REQUEST
            )

        project = get_object_or_404(Project, pk=project_id)

        # Verify that the uploader belongs to the project's team.
        is_member = TeamMembership.objects.filter(
            team=project.team,
            user=request.user
        ).exists()

        if not is_member:
            return Response(
                {"error": "You are not a member of this project's team."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Calculate the hash from the actual uploaded file.
        file_hash = calculate_sha256(uploaded_file)

        # Store the artifact and its first version.
        with transaction.atomic():
            artifact = Artifact.objects.create(
                project=project,
                name=request.data.get("name") or uploaded_file.name,
                description=request.data.get("description", ""),
                uploaded_by=request.user,
                current_version=1
            )

            original_filename = os.path.basename(
                uploaded_file.name.replace("\\", "/")
            )[:255]

            version = ArtifactVersion.objects.create(
                artifact=artifact,
                version_number=1,
                file=uploaded_file,
                original_filename=original_filename,
                sha256_hash=file_hash,
                file_size=uploaded_file.size,
                uploaded_by=request.user
            )

        serializer = ArtifactSerializer(artifact)

        return Response(
            {
                "message": "Artifact uploaded successfully.",
                "artifact": serializer.data,
                "sha256_hash": version.sha256_hash,
            },
            status=status.HTTP_201_CREATED
        )

class ArtifactVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, artifact_id):
        """
        Verify an artifact version by recalculating
        its SHA-256 hash and comparing it with the stored hash.
        """

        # Only allow members of the project's team to access it.
        artifact = get_accessible_artifact(
            artifact_id,
            request.user,
            permission="view"
        )

        # Optional version_number query parameter.
        version_number = request.query_params.get("version")

        if version_number is not None:
            try:
                version_number = int(version_number)
                if version_number < 1:
                    raise ValueError
            except (ValueError, TypeError):
                return Response(
                    {"error": "Version must be a positive integer."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        else:
            version_number = artifact.current_version

        version = get_object_or_404(
            ArtifactVersion,
            artifact=artifact,
            version_number=version_number
        )

        try:
            result = verify_artifact_version(version)

        except (OSError, ValueError) as error:
            return Response(
                {
                    "error": "Could not read the stored artifact file.",
                    "details": str(error)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {
                "message": (
                    "Artifact integrity verified successfully."
                    if result["is_valid"]
                    else "Artifact integrity verification failed."
                ),
                "artifact_id": artifact.id,
                "artifact_name": artifact.name,
                "version_number": version.version_number,
                "original_hash": result["expected_hash"],
                "calculated_hash": result["actual_hash"],
                "is_valid": result["is_valid"],
            },
            status=status.HTTP_200_OK
        )


class ArtifactDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, artifact_id):
        """Download an artifact only when the user has download permission."""

        artifact = get_accessible_artifact(
            artifact_id,
            request.user,
            permission="download"
        )

        # The uploader always has access.
        is_owner = artifact.uploaded_by_id == request.user.id

        # Other users need an explicit download permission.
        has_download_permission = ArtifactAccess.objects.filter(
            artifact=artifact,
            user=request.user,
            permission="download"
        ).exists()

        if not is_owner and not has_download_permission:
            return Response(
                {"error": "You do not have permission to download this artifact."},
                status=status.HTTP_403_FORBIDDEN
            )

        version_number = request.query_params.get("version")

        if version_number is not None:
            try:
                version_number = int(version_number)
                if version_number < 1:
                    raise ValueError
            except (ValueError, TypeError):
                return Response(
                    {"error": "Version must be a positive integer."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            version_number = artifact.current_version

        version = get_object_or_404(
            ArtifactVersion,
            artifact=artifact,
            version_number=version_number
        )

        try:
            file_handle = version.file.open("rb")
        except (OSError, ValueError):
            return Response(
                {"error": "Stored artifact file is unavailable."},
                status=status.HTTP_404_NOT_FOUND
            )

        return FileResponse(
            file_handle,
            as_attachment=True,
            filename=version.original_filename
        )


class ArtifactVersionListCreateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_artifact(self, artifact_id, user):
        return get_accessible_artifact(
            artifact_id,
            user,
            permission="view"
        )

    def get(self, request, artifact_id):
        """Return the complete version history."""

        artifact = self.get_artifact(artifact_id, request.user)

        versions = artifact.versions.select_related(
            "uploaded_by"
        ).order_by("-version_number")

        serializer = ArtifactVersionSerializer(
            versions,
            many=True
        )

        return Response({
            "artifact_id": artifact.id,
            "artifact_name": artifact.name,
            "current_version": artifact.current_version,
            "total_versions": versions.count(),
            "versions": serializer.data
        })

    def post(self, request, artifact_id):
        """Upload a new version without replacing older versions."""

        uploaded_file = request.FILES.get("file")

        if not uploaded_file:
            return Response(
                {"error": "Please select a file."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if uploaded_file.size > 100 * 1024 * 1024:
            return Response(
                {"error": "File size cannot exceed 100 MB."},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            artifact = get_object_or_404(
                Artifact.objects.select_for_update(),
                pk=artifact_id
            )

            if not user_can_upload_version(artifact, request.user):
                raise PermissionDenied(
                    "Only the artifact owner can upload a new version."
                )

            next_version = (
                artifact.versions.aggregate(
                    maximum=models.Max("version_number")
                )["maximum"] or 0
            ) + 1

            original_filename = os.path.basename(
                uploaded_file.name.replace("\\", "/")
            )[:255]

            file_hash = calculate_sha256(uploaded_file)

            version = ArtifactVersion.objects.create(
                artifact=artifact,
                version_number=next_version,
                file=uploaded_file,
                original_filename=original_filename,
                sha256_hash=file_hash,
                file_size=uploaded_file.size,
                uploaded_by=request.user
            )

            artifact.current_version = next_version
            artifact.save(update_fields=[
                "current_version",
                "updated_at"
            ])

        serializer = ArtifactVersionSerializer(version)

        return Response({
            "message": "New artifact version uploaded successfully.",
            "artifact_id": artifact.id,
            "current_version": artifact.current_version,
            "version": serializer.data
        }, status=status.HTTP_201_CREATED)

class ArtifactShareView(APIView):
    permission_classes = [IsAuthenticated]

    def get_owned_artifact(self, artifact_id, user):
        return get_object_or_404(
            Artifact,
            pk=artifact_id,
            uploaded_by=user
        )

    def post(self, request, artifact_id):
        """Share an artifact with another member of its project team."""

        artifact = self.get_owned_artifact(artifact_id, request.user)

        username = request.data.get("username", "").strip()
        permission = request.data.get("permission", "view")

        if not username:
            return Response(
                {"error": "Username is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if permission not in ("view", "download"):
            return Response(
                {"error": "Permission must be 'view' or 'download'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        if user.id == request.user.id:
            return Response(
                {"error": "You already have owner access."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Sharing is restricted to members of the same project team.
        is_team_member = TeamMembership.objects.filter(
            team=artifact.project.team,
            user=user
        ).exists()

        if not is_team_member:
            return Response(
                {"error": "The user is not a member of this project's team."},
                status=status.HTTP_403_FORBIDDEN
            )

        grant, created = ArtifactAccess.objects.update_or_create(
            artifact=artifact,
            user=user,
            defaults={
                "permission": permission,
                "granted_by": request.user
            }
        )

        serializer = ArtifactAccessSerializer(grant)

        return Response(
            {
                "message": (
                    "Artifact access granted."
                    if created else "Artifact access updated."
                ),
                "access": serializer.data
            },
            status=(
                status.HTTP_201_CREATED
                if created else status.HTTP_200_OK
            )
        )

    def delete(self, request, artifact_id, user_id):
        """Revoke a previously granted permission."""

        artifact = self.get_owned_artifact(artifact_id, request.user)

        deleted, _ = ArtifactAccess.objects.filter(
            artifact=artifact,
            user_id=user_id
        ).delete()

        if not deleted:
            return Response(
                {"error": "No access grant found for this user."},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response(
            {"message": "Artifact access revoked."},
            status=status.HTTP_200_OK
        )
