# microsoft-sso-authentication-platform-93221-93230

## Django Backend SSO Authentication

This Django backend supports Microsoft (Azure AD) Single Sign-On integration using OAuth2/OpenID Connect.

### Setup

1. Create an Azure AD App Registration (see Azure Portal) and note:
    - Client ID
    - Client Secret
    - Redirect URI (should be set to `<backend>/api/auth/callback/`)

2. Copy `.env.example` to `.env` and fill in your Azure details.

3. Install requirements:

    ```
    pip install -r requirements.txt
    ```

4. Run Django server:

    ```
    python manage.py runserver 0.0.0.0:3001
    ```

### Auth Endpoints

- `GET /api/auth/login/` — Get Microsoft login URL (frontend should redirect user here)
- `GET /api/auth/callback/` — Azure AD redirect/callback handler (should match Redirect URI in Azure)
- `GET /api/auth/logout/` — Log out user and clear Microsoft session
- `GET /api/auth/session/` — Get current session/authenticated user info
- `GET /api/auth/error/` — Show generic authentication error

All endpoints are CSRF-exempt for API compatibility.
