import os
import uuid
import json
import requests
from urllib.parse import urlencode, quote

from django.conf import settings
from django.contrib.auth import login, logout, get_user_model
from django.http import JsonResponse, HttpResponseRedirect, HttpResponseBadRequest, HttpResponseServerError
from django.views.decorators.csrf import csrf_exempt

# PUBLIC_INTERFACE
def get_env_setting(key, default=None):
    """Fetch environment variable or Django setting fallback."""
    return os.environ.get(key) or getattr(settings, key, default) or default


# PUBLIC_INTERFACE
def get_azure_ad_config():
    """Return Azure AD config from environment or settings."""
    return {
        "CLIENT_ID": get_env_setting("AZURE_AD_CLIENT_ID"),
        "CLIENT_SECRET": get_env_setting("AZURE_AD_CLIENT_SECRET"),
        "AUTHORITY": get_env_setting("AZURE_AD_AUTHORITY", "https://login.microsoftonline.com/common"),
        "REDIRECT_URI": get_env_setting("AZURE_AD_REDIRECT_URI"),
        "SCOPE": get_env_setting("AZURE_AD_SCOPE", "openid profile email"),
        "FRONTEND_SUCCESS_URL": get_env_setting("FRONTEND_SUCCESS_URL", "/"),
        "FRONTEND_ERROR_URL": get_env_setting("FRONTEND_ERROR_URL", "/login"),
    }


# PUBLIC_INTERFACE
def build_auth_url(state):
    """Generate Azure AD auth URL."""
    cfg = get_azure_ad_config()
    params = {
        "client_id": cfg["CLIENT_ID"],
        "response_type": "code",
        "redirect_uri": cfg["REDIRECT_URI"],
        "response_mode": "query",
        "scope": cfg["SCOPE"],
        "state": state,
        "prompt": "select_account",
    }
    return f'{cfg["AUTHORITY"]}/oauth2/v2.0/authorize?{urlencode(params)}'


# PUBLIC_INTERFACE
def get_token_from_code(auth_code):
    """Exchange code for tokens using Azure AD's /token endpoint."""
    cfg = get_azure_ad_config()
    token_url = f'{cfg["AUTHORITY"]}/oauth2/v2.0/token'
    data = {
        "client_id": cfg["CLIENT_ID"],
        "scope": cfg["SCOPE"],
        "code": auth_code,
        "redirect_uri": cfg["REDIRECT_URI"],
        "grant_type": "authorization_code",
        "client_secret": cfg["CLIENT_SECRET"],
    }
    resp = requests.post(token_url, data=data)
    if resp.status_code != 200:
        return None, resp.text
    return resp.json(), None


# PUBLIC_INTERFACE
def get_user_profile(token):
    """Get user profile info from the Microsoft Graph API using id token."""
    headers = {
        "Authorization": f'Bearer {token}',
        "Content-Type": "application/json"
    }
    resp = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
    if resp.status_code == 200:
        return resp.json()
    return None


# PUBLIC_INTERFACE
def get_or_create_user_from_profile(profile):
    """Get or create a local Django user from a Microsoft Graph profile."""
    User = get_user_model()
    email = profile.get("mail") or profile.get("userPrincipalName")
    if not email:
        return None
    try:
        user, _ = User.objects.get_or_create(username=email, defaults={"email": email})
    except Exception:  # fallback to lookup just in case
        user = User.objects.filter(email=email).first()
        if not user:
            return None
    return user


# PUBLIC_INTERFACE
@csrf_exempt
def sso_auth_init(request):
    """
    Initiate SSO login (redirect user to Azure AD).
    GET /api/auth/login/
    """
    state = str(uuid.uuid4())  # In prod, consider persisting state
    # Optionally save state in session for CSRF
    request.session["oauth_state"] = state
    auth_url = build_auth_url(state)
    return JsonResponse({"auth_url": auth_url})


# PUBLIC_INTERFACE
@csrf_exempt
def sso_auth_callback(request):
    """
    Callback endpoint for Azure AD authentication (handles redirect from Azure).
    GET /api/auth/callback/?code=...&state=...
    """
    code = request.GET.get("code")
    state = request.GET.get("state")
    session_state = request.session.get("oauth_state")

    if not code or not state or state != session_state:
        return HttpResponseBadRequest(json.dumps({"error": "Invalid or missing state/code."}), content_type="application/json")

    token_data, err = get_token_from_code(code)
    if err or not token_data:
        return HttpResponseServerError(json.dumps({"error": "Token exchange failed", "details": err}), content_type="application/json")

    access_token = token_data.get("access_token")
    profile = get_user_profile(access_token)
    if not profile:
        return HttpResponseServerError(json.dumps({"error": "Failed to fetch profile"}), content_type="application/json")

    user = get_or_create_user_from_profile(profile)
    if not user:
        return HttpResponseServerError(json.dumps({"error": "Failed to create user from Microsoft account"}), content_type="application/json")

    login(request, user)
    # Upon successful login, send session info or success response
    frontend_url = get_env_setting("FRONTEND_SUCCESS_URL", "/")
    return HttpResponseRedirect(frontend_url)  # or return token/session info as JSON


# PUBLIC_INTERFACE
@csrf_exempt
def sso_logout(request):
    """
    Log out Django session and redirect to Microsoft logout.
    GET /api/auth/logout/
    """
    logout(request)
    # Redirect to Microsoft logout endpoint with post_logout_redirect_uri
    cfg = get_azure_ad_config()
    microsoft_logout = (
        f'{cfg["AUTHORITY"]}/oauth2/v2.0/logout'
        f'?post_logout_redirect_uri={quote(cfg["FRONTEND_SUCCESS_URL"])}'
    )
    return HttpResponseRedirect(microsoft_logout)


# PUBLIC_INTERFACE
@csrf_exempt
def sso_session(request):
    """
    Return authenticated user info (if any) for session management.
    GET /api/auth/session/
    """
    if request.user.is_authenticated:
        return JsonResponse({
            "authenticated": True,
            "username": request.user.username,
            "email": request.user.email,
            "id": request.user.id,
        })
    else:
        return JsonResponse({"authenticated": False})


# PUBLIC_INTERFACE
@csrf_exempt
def sso_error(request):
    """
    Endpoint for handling auth errors (optional).
    GET /api/auth/error/
    """
    message = request.GET.get("message", "An error occurred during authentication.")
    return JsonResponse({"authenticated": False, "error": message})

