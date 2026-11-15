from django.urls import path
from . import views

urlpatterns = [
    path("server-info/", views.ServerInfoView.as_view()),
    path("contacts/", views.ContactsView.as_view()),
    path("unread/", views.UnreadView.as_view()),
    path("notifications/", views.NotificationsView.as_view()),
    path("notifications/read/", views.MarkReadView.as_view()),
    path("channels/<int:channel_id>/messages/", views.ChannelMessagesView.as_view()),
    path("dm/<int:user_id>/messages/", views.DirectMessagesView.as_view()),
]
