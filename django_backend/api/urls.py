from django.urls import path
from .views import health
from . import sso

urlpatterns = [
    path('health/', health, name='Health'),
    # Microsoft SSO endpoints:
    path('auth/login/', sso.sso_auth_init, name='sso_auth_init'),  # get Microsoft login redirect URL
    path('auth/callback/', sso.sso_auth_callback, name='sso_auth_callback'),  # Azure redirect URI
    path('auth/logout/', sso.sso_logout, name='sso_logout'),
    path('auth/session/', sso.sso_session, name='sso_session'),
    path('auth/error/', sso.sso_error, name='sso_error'),
]
