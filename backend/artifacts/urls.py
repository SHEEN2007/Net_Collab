
from django.urls import path

from .views import (
    ArtifactListUploadView,
    ArtifactVerifyView,
    ArtifactDownloadView,
    ArtifactVersionListCreateView,
    ArtifactShareView,
)

urlpatterns = [
    path("", ArtifactListUploadView.as_view(), name="artifact-list"),
    path("upload/", ArtifactListUploadView.as_view(), name="artifact-upload"),

    path(
        "<int:artifact_id>/verify/",
        ArtifactVerifyView.as_view(),
        name="artifact-verify"
    ),
    path(
        "<int:artifact_id>/download/",
        ArtifactDownloadView.as_view(),
        name="artifact-download"
    ),
    path(
        "<int:artifact_id>/versions/",
        ArtifactVersionListCreateView.as_view(),
        name="artifact-versions"
    ),
    path(
        "<int:artifact_id>/share/",
        ArtifactShareView.as_view(),
        name="artifact-share"
    ),
    path(
        "<int:artifact_id>/share/<int:user_id>/",
        ArtifactShareView.as_view(),
        name="artifact-revoke-share"
    ),
]
