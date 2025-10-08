from django.contrib import admin
from django.urls import path, include
from .views import *


urlpatterns = [
    # --- User Login, Logout, Profile ---
    path('login/', UserLoginAPIView.as_view(), name='user-login'),
    path('logout/', UserLogoutAPIView.as_view(), name='user-logout'),
    path('register/', UserRegisterAPIView.as_view(), name='user-register'),
    path('changepassword/', ChangePasswordAPIView.as_view(), name='change-password'),
    path('profile/view/', UserProfileViewAPIView.as_view(), name='user-profile-view'),
    path('profile/update/', UserProfileUpdateAPIView.as_view(), name='user-profile-update'),
    
    # --- User Notes ---
    path('notes/create', CreateNoteAPIView.as_view(), name='user-notes-create'),
    path('notes/list', ListNotesAPIView.as_view(), name='user-notes-list'),
    path('notes/<int:note_id>/update', UpdateNoteAPIView.as_view(), name='user-notes-update'),
    path('notes/<int:note_id>/delete', DeleteNoteAPIView.as_view(), name='user-notes-delete'),
]