import os
from accounts.models import Profile
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
import base64

from django.core.files.base import ContentFile

from .models import ArtifactVersionKey

from .services.encryption import (
    generate_aes_key,
    encrypt_file_data,
)
from .services.key_exchange import (
    load_recipient_public_key,
    wrap_aes_key,
)
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
        """Upload and encrypt a new artifact."""

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

        if uploaded_file.size > 100 * 1024 * 1024:
            return Response(
                {"error": "File size cannot exceed 100 MB."},
                status=status.HTTP_400_BAD_REQUEST
            )

        project = get_object_or_404(Project, pk=project_id)

        is_member = TeamMembership.objects.filter(
            team=project.team,
            user=request.user
        ).exists()

        if not is_member:
            return Response(
                {"error": "You are not a member of this project's team."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Retrieve the uploader's registered RSA public key.
        profile = Profile.objects.filter(user=request.user).first()

        if not profile or not profile.public_key:
            return Response(
                {
                    "error": (
                        "Register your RSA public key before "
                        "uploading encrypted artifacts."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Calculate SHA-256 from the original plaintext.
        file_hash = calculate_sha256(uploaded_file)

        # Read original file bytes.
        uploaded_file.seek(0)
        file_data = uploaded_file.read()

        # Generate AES key and encrypt the file.
        aes_key = generate_aes_key()
        encrypted_file = encrypt_file_data(file_data, aes_key)

        ciphertext = base64.b64decode(
            encrypted_file["ciphertext"]
        )

        # Wrap AES key for the uploader.
        recipient_public_key = load_recipient_public_key(
            profile.public_key
        )

        wrapped_key = wrap_aes_key(
            aes_key,
            recipient_public_key
        )

        original_filename = os.path.basename(
            uploaded_file.name.replace("\\", "/")
        )[:255]

        # Store encrypted artifact and key metadata.
        with transaction.atomic():
            artifact = Artifact.objects.create(
                project=project,
                name=request.data.get("name") or uploaded_file.name,
                description=request.data.get("description", ""),
                uploaded_by=request.user,
                current_version=1
            )

            version = ArtifactVersion.objects.create(
                artifact=artifact,
                version_number=1,
                file=ContentFile(
                    ciphertext,
                    name=original_filename + ".enc"
                ),
                original_filename=original_filename,
                sha256_hash=file_hash,
                file_size=uploaded_file.size,
                uploaded_by=request.user,
                is_encrypted=True,
                encryption_algorithm="AES-256-GCM",
                encryption_nonce=encrypted_file["nonce"],
                encrypted_file_size=len(ciphertext)
            )

            ArtifactVersionKey.objects.create(
                version=version,
                recipient=request.user,
                wrapped_key=wrapped_key,
                key_encryption_algorithm="RSA-OAEP-SHA256",
                recipient_key_id=profile.key_fingerprint
            )

        serializer = ArtifactSerializer(artifact)

        return Response(
            {
                "message": "Encrypted artifact uploaded successfully.",
                "artifact": serializer.data,
                "sha256_hash": file_hash,
                "encryption": "AES-256-GCM",
                "key_encryption": "RSA-OAEP-SHA256",
                "wrapped_key": wrapped_key,
                "encrypted_file_size": len(ciphertext)
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
        """Return encrypted artifact bytes and the requesting user's wrapped key."""

        artifact = get_accessible_artifact(
            artifact_id,
            request.user,
            permission="download"
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

        # Find the AES key wrapped specifically for this recipient.
        key_record = ArtifactVersionKey.objects.filter(
            version=version,
            recipient=request.user
        ).first()

        if version.is_encrypted and not key_record:
            return Response(
                {
                    "error": (
                        "No encryption key is available for your account. "
                        "Ask the artifact owner to share access securely."
                    )
                },
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            file_handle = version.file.open("rb")
        except (OSError, ValueError):
            return Response(
                {"error": "Stored artifact file is unavailable."},
                status=status.HTTP_404_NOT_FOUND
            )

        filename = (
            version.original_filename
            if not version.is_encrypted
            else version.original_filename + ".enc"
        )

        response = FileResponse(
            file_handle,
            as_attachment=True,
            filename=filename
        )

        response["X-Artifact-Encrypted"] = str(
            version.is_encrypted
        ).lower()

        response["X-Artifact-SHA256"] = version.sha256_hash
        response["X-Artifact-Original-Filename"] = base64.b64encode(
            version.original_filename.encode("utf-8")
        ).decode("ascii")

        if version.is_encrypted:
            response["X-Artifact-Algorithm"] = (
                version.encryption_algorithm
            )
            response["X-Artifact-Nonce"] = version.encryption_nonce
            response["X-Artifact-Wrapped-Key"] = key_record.wrapped_key
            response["X-Artifact-Key-Algorithm"] = (
                key_record.key_encryption_algorithm
            )

        return response


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
        """Upload a new encrypted artifact version."""

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

        profile = Profile.objects.filter(user=request.user).first()

        if not profile or not profile.public_key:
            return Response(
                {"error": "Register your RSA public key first."},
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

            file_hash = calculate_sha256(uploaded_file)

            uploaded_file.seek(0)
            file_data = uploaded_file.read()

            aes_key = generate_aes_key()
            encrypted_file = encrypt_file_data(file_data, aes_key)

            ciphertext = base64.b64decode(
                encrypted_file["ciphertext"]
            )

            recipient_public_key = load_recipient_public_key(
                profile.public_key
            )

            wrapped_key = wrap_aes_key(
                aes_key,
                recipient_public_key
            )

            original_filename = os.path.basename(
                uploaded_file.name.replace("\\", "/")
            )[:255]

            version = ArtifactVersion.objects.create(
                artifact=artifact,
                version_number=next_version,
                file=ContentFile(
                    ciphertext,
                    name=original_filename + ".enc"
                ),
                original_filename=original_filename,
                sha256_hash=file_hash,
                file_size=uploaded_file.size,
                uploaded_by=request.user,
                is_encrypted=True,
                encryption_algorithm="AES-256-GCM",
                encryption_nonce=encrypted_file["nonce"],
                encrypted_file_size=len(ciphertext)
            )

            ArtifactVersionKey.objects.create(
                version=version,
                recipient=request.user,
                wrapped_key=wrapped_key,
                key_encryption_algorithm="RSA-OAEP-SHA256",
                recipient_key_id=profile.key_fingerprint
            )

            artifact.current_version = next_version
            artifact.save(update_fields=[
                "current_version",
                "updated_at"
            ])

        serializer = ArtifactVersionSerializer(version)

        return Response({
            "message": "Encrypted artifact version uploaded successfully.",
            "artifact_id": artifact.id,
            "current_version": artifact.current_version,
            "version": serializer.data,
            "wrapped_key": wrapped_key,
            "sha256_hash": file_hash
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
        """
        Share an artifact using recipient-specific RSA-wrapped AES keys.

        The browser must unwrap and rewrap each AES key locally.
        The backend receives only the recipient's wrapped keys.
        """

        artifact = self.get_owned_artifact(
            artifact_id,
            request.user
        )

        username = request.data.get("username", "").strip()
        permission = request.data.get("permission", "view")
        wrapped_keys = request.data.get("wrapped_keys")

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

        if not isinstance(wrapped_keys, list) or not wrapped_keys:
            return Response(
                {
                    "error": (
                        "Recipient-specific wrapped keys are required "
                        "for every encrypted artifact version."
                    )
                },
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

        is_team_member = TeamMembership.objects.filter(
            team=artifact.project.team,
            user=user
        ).exists()

        if not is_team_member:
            return Response(
                {
                    "error": (
                        "The user is not a member of this project's team."
                    )
                },
                status=status.HTTP_403_FORBIDDEN
            )

        recipient_profile = Profile.objects.filter(
            user=user
        ).first()

        if not recipient_profile or not recipient_profile.public_key:
            return Response(
                {
                    "error": (
                        "The recipient must register an RSA public key "
                        "before receiving encrypted artifacts."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        encrypted_versions = list(
            ArtifactVersion.objects.filter(
                artifact=artifact,
                is_encrypted=True
            ).values_list("id", flat=True)
        )

        if not encrypted_versions:
            return Response(
                {"error": "This artifact has no encrypted versions to share."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate the supplied version IDs and wrapped keys.
        supplied_keys = {}

        for item in wrapped_keys:
            if not isinstance(item, dict):
                return Response(
                    {"error": "Each wrapped key must be an object."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            version_id = item.get("version_id")
            wrapped_key = item.get("wrapped_key")

            try:
                version_id = int(version_id)
            except (ValueError, TypeError):
                return Response(
                    {"error": "Each key requires a valid version_id."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not isinstance(wrapped_key, str) or not wrapped_key.strip():
                return Response(
                    {"error": "Each version requires a wrapped AES key."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if version_id in supplied_keys:
                return Response(
                    {"error": "Duplicate version IDs were supplied."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            supplied_keys[version_id] = wrapped_key.strip()

        if set(supplied_keys.keys()) != set(encrypted_versions):
            return Response(
                {
                    "error": (
                        "Wrapped keys must be supplied for every encrypted "
                        "version of this artifact, and no other versions."
                    ),
                    "required_version_ids": encrypted_versions
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Grant access and store recipient-specific wrapped keys atomically.
        with transaction.atomic():
            grant, created = ArtifactAccess.objects.update_or_create(
                artifact=artifact,
                user=user,
                defaults={
                    "permission": permission,
                    "granted_by": request.user
                }
            )

            for version_id, wrapped_key in supplied_keys.items():
                ArtifactVersionKey.objects.update_or_create(
                    version_id=version_id,
                    recipient=user,
                    defaults={
                        "wrapped_key": wrapped_key,
                        "key_encryption_algorithm": "RSA-OAEP-SHA256",
                        "recipient_key_id": (
                            recipient_profile.key_fingerprint
                        )
                    }
                )

        serializer = ArtifactAccessSerializer(grant)

        return Response(
            {
                "message": (
                    "Encrypted artifact access granted."
                    if created
                    else "Encrypted artifact access updated."
                ),
                "access": serializer.data,
                "recipient": user.username,
                "wrapped_versions": len(supplied_keys)
            },
            status=(
                status.HTTP_201_CREATED
                if created else status.HTTP_200_OK
            )
        )

    def delete(self, request, artifact_id, user_id):
        """Revoke access and delete the recipient's wrapped keys."""

        artifact = self.get_owned_artifact(
            artifact_id,
            request.user
        )

        with transaction.atomic():
            grant = ArtifactAccess.objects.select_for_update().filter(
                artifact=artifact,
                user_id=user_id
            ).first()

            if not grant:
                return Response(
                    {"error": "No access grant found for this user."},
                    status=status.HTTP_404_NOT_FOUND
                )

            grant.delete()

            ArtifactVersionKey.objects.filter(
                version__artifact=artifact,
                recipient_id=user_id
            ).delete()

        return Response(
            {
                "message": (
                    "Artifact access revoked and recipient key records deleted."
                )
            },
            status=status.HTTP_200_OK
        )

class ArtifactSharingKeysView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, artifact_id):
        """
        Return the owner's RSA-wrapped AES keys for every encrypted
        version. The browser unwraps and rewraps them for the recipient.
        """

        artifact = get_object_or_404(
            Artifact,
            pk=artifact_id,
            uploaded_by=request.user
        )

        versions = ArtifactVersion.objects.filter(
            artifact=artifact,
            is_encrypted=True
        ).order_by("version_number")

        sharing_keys = []

        for version in versions:
            key_record = ArtifactVersionKey.objects.filter(
                version=version,
                recipient=request.user
            ).first()

            if not key_record:
                return Response(
                    {
                        "error": (
                            f"Your encryption key is missing for "
                            f"version {version.version_number}."
                        )
                    },
                    status=status.HTTP_409_CONFLICT
                )

            sharing_keys.append({
                "version_id": version.id,
                "version_number": version.version_number,
                "wrapped_key": key_record.wrapped_key,
                "key_encryption_algorithm": (
                    key_record.key_encryption_algorithm
                ),
                "recipient_key_id": key_record.recipient_key_id
            })

        return Response({
            "artifact_id": artifact.id,
            "artifact_name": artifact.name,
            "total_versions": len(sharing_keys),
            "sharing_keys": sharing_keys
        }, status=status.HTTP_200_OK)
class ArtifactRecipientsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, artifact_id):
        """Return existing artifact recipients and their public keys."""

        artifact = get_object_or_404(
            Artifact,
            pk=artifact_id,
            uploaded_by=request.user
        )

        grants = ArtifactAccess.objects.filter(
            artifact=artifact
        ).select_related("user")

        recipients = []

        for grant in grants:
            profile = Profile.objects.filter(
                user=grant.user
            ).first()

            if not profile or not profile.public_key:
                return Response(
                    {
                        "error": (
                            f"{grant.user.username} has not registered "
                            "an RSA public key."
                        )
                    },
                    status=status.HTTP_409_CONFLICT
                )

            recipients.append({
                "user_id": grant.user.id,
                "username": grant.user.username,
                "permission": grant.permission,
                "public_key": profile.public_key,
                "key_fingerprint": profile.key_fingerprint
            })

        return Response({
            "artifact_id": artifact.id,
            "recipients": recipients
        }, status=status.HTTP_200_OK)

class ArtifactVersionRecipientKeysView(APIView):
    permission_classes = [IsAuthenticated]


    def post(self, request, artifact_id, version_id):
        artifact = get_object_or_404(
            Artifact,
            pk=artifact_id,
            uploaded_by=request.user
        )

        version = get_object_or_404(
            ArtifactVersion,
            pk=version_id,
            artifact=artifact,
            is_encrypted=True
        )

        wrapped_keys = request.data.get("wrapped_keys")

        if not isinstance(wrapped_keys, list):
            return Response(
                {"error": "wrapped_keys must be a list."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get all existing recipients.
        grants = list(
            ArtifactAccess.objects.filter(
                artifact=artifact
            ).select_related("user")
        )

        expected_ids = {grant.user_id for grant in grants}
        supplied_keys = {}

        for item in wrapped_keys:
            if not isinstance(item, dict):
                return Response(
                    {"error": "Invalid wrapped key entry."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                user_id = int(item.get("user_id"))
            except (ValueError, TypeError):
                return Response(
                    {"error": "Invalid recipient user ID."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            wrapped_key = item.get("wrapped_key")

            if not isinstance(wrapped_key, str) or not wrapped_key.strip():
                return Response(
                    {"error": "A wrapped AES key is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if user_id in supplied_keys:
                return Response(
                    {"error": "Duplicate recipients supplied."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            supplied_keys[user_id] = wrapped_key.strip()

        if set(supplied_keys) != expected_ids:
            return Response(
                {
                    "error": "Keys must be supplied for every existing recipient.",
                    "expected_recipient_ids": sorted(expected_ids)
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate every recipient before writing anything.
        recipient_profiles = {}

        for grant in grants:
            profile = Profile.objects.filter(
                user=grant.user
            ).first()

            if not profile or not profile.public_key:
                return Response(
                    {
                        "error": (
                            f"{grant.user.username} has no registered "
                            "public key."
                        )
                    },
                    status=status.HTTP_409_CONFLICT
                )

            recipient_profiles[grant.user_id] = profile

        # Save all recipient keys atomically.
        with transaction.atomic():
            for grant in grants:
                profile = recipient_profiles[grant.user_id]

                ArtifactVersionKey.objects.update_or_create(
                    version=version,
                    recipient=grant.user,
                    defaults={
                        "wrapped_key": supplied_keys[grant.user_id],
                        "key_encryption_algorithm": "RSA-OAEP-SHA256",
                        "recipient_key_id": profile.key_fingerprint
                    }
                )

        return Response(
            {
                "message": "Recipient keys stored successfully.",
                "version_id": version.id,
                "recipients_updated": len(grants)
            },
            status=status.HTTP_200_OK
        )


        return Response({
            "message": "Recipient keys stored successfully.",
            "version_id": version.id,
            "recipients_updated": len(grants)
        }, status=status.HTTP_200_OK)