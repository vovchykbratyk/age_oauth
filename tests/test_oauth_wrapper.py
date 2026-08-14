from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import age_oauth.oauth as oauth_module
from age_oauth.envfile import parse_env_file
from age_oauth.oauth import (
    AGEOAuth,
    OAuthConfig,
    OAuthIdentity,
    get_gis,
    get_username_via_rest,
    resolve_identity,
    resolve_live_username,
)


PORTAL = "https://enterprise.example.test/portal"
CLIENT_ID = "client-123"
CLIENT_SECRET = "secret-456"
REFERER = "https://localhost"


def _write_env(
    tmp_path: Path,
    *,
    auth_type: str | None = "user",
    referer: str | None = None,
    access_token: str = "",
    refresh_token: str = "",
    username: str = "",
    expires_at: str = "0",
) -> Path:
    """
    Create a minimal age-oauth connection .env for unit tests.
    """
    env_path = tmp_path / ".env"

    lines = [
        f"PORTAL_URL='{PORTAL}'",
        f"OAUTH_CLIENT_ID='{CLIENT_ID}'",
        f"OAUTH_CLIENT_SECRET='{CLIENT_SECRET}'",
        "OAUTH_VERIFY_SSL='false'",
        f"OAUTH_ACCESS_TOKEN='{access_token}'",
        f"OAUTH_REFRESH_TOKEN='{refresh_token}'",
        f"OAUTH_USERNAME='{username}'",
        f"OAUTH_TOKEN_EXPIRES_AT='{expires_at}'",
    ]

    if auth_type is not None:
        lines.append(f"OAUTH_AUTH_TYPE='{auth_type}'")

    if referer is not None:
        lines.append(f"OAUTH_REFERER='{referer}'")

    env_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return env_path


def _build_auth(
    env_path: Path,
    *,
    auth_type: str = "user",
) -> AGEOAuth:
    return AGEOAuth(
        OAuthConfig(
            portal_url=PORTAL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            env_path=str(env_path),
            auth_type=auth_type,
        )
    )


class FakeResponse:
    def __init__(
        self,
        payload,
        *,
        ok: bool = True,
        status_code: int = 200,
        text: str = "",
    ):
        self._payload = payload
        self.ok = ok
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._payload


# ---------------------------------------------------------------------------
# Connection/auth-mode behavior
# ---------------------------------------------------------------------------


def test_legacy_connection_defaults_to_user(tmp_path):
    """
    Pre-0.2.0 connection profiles have no OAUTH_AUTH_TYPE.
    They must continue to behave as user-authenticated connections.
    """

    env_path = _write_env(
        tmp_path,
        auth_type=None,
    )

    auth = _build_auth(
        env_path,
        auth_type="user",
    )

    assert auth.auth_type == "user"


def test_app_auth_uses_client_credentials(tmp_path, monkeypatch):
    """
    App auth must request a token using exactly the client_credentials grant.
    It must not send user-flow fields.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
        referer=REFERER,
    )

    captured = {}

    def fake_post(url, *, data, headers, timeout, verify):
        captured["url"] = url
        captured["data"] = dict(data)
        captured["headers"] = dict(headers)
        captured["timeout"] = timeout
        captured["verify"] = verify

        return FakeResponse(
            {
                "access_token": "app-token-123",
                "expires_in": 3600,
            }
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        fake_post,
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    token = auth.access_token

    assert token == "app-token-123"

    assert captured["url"] == (
        f"{PORTAL}/sharing/rest/oauth2/token"
    )

    assert captured["data"]["client_id"] == CLIENT_ID
    assert captured["data"]["client_secret"] == CLIENT_SECRET
    assert captured["data"]["grant_type"] == "client_credentials"
    assert captured["data"]["f"] == "json"

    assert "redirect_uri" not in captured["data"]
    assert "code" not in captured["data"]
    assert "refresh_token" not in captured["data"]

    assert captured["headers"]["Referer"] == REFERER
    assert captured["verify"] is False


def test_app_auth_never_opens_browser(tmp_path, monkeypatch):
    """
    Accessing an app token must never invoke interactive authentication.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
    )

    def browser_must_not_open(*args, **kwargs):
        raise AssertionError(
            "webbrowser.open() was called during app authentication"
        )

    monkeypatch.setattr(
        oauth_module.webbrowser,
        "open",
        browser_must_not_open,
    )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "access_token": "app-token",
                "expires_in": 3600,
            }
        ),
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    assert auth.access_token == "app-token"


def test_app_auth_clears_user_state(tmp_path, monkeypatch):
    """
    Changing/reusing a profile for app auth must not leave stale user
    identity or refresh-token state behind.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
        refresh_token="stale-user-refresh-token",
        username="old.user@example.test",
    )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "access_token": "new-app-token",
                "expires_in": 3600,
            }
        ),
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    assert auth.access_token == "new-app-token"

    env = parse_env_file(env_path)

    assert env.get("OAUTH_REFRESH_TOKEN", "") == ""
    assert env.get("OAUTH_USERNAME", "") == ""


def test_expired_app_token_is_reacquired(
    tmp_path,
    monkeypatch,
):
    """
    An expired cached app token must be replaced using client_credentials.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
        access_token="expired-app-token",
        expires_at="1",
    )

    captured = {
        "calls": 0,
    }

    def fake_post(url, *, data, headers, timeout, verify):
        captured["calls"] += 1
        captured["data"] = dict(data)

        return FakeResponse(
            {
                "access_token": "fresh-app-token",
                "expires_in": 3600,
            }
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        fake_post,
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    token = auth.access_token

    assert token == "fresh-app-token"
    assert captured["calls"] == 1
    assert captured["data"]["grant_type"] == "client_credentials"

    env = parse_env_file(env_path)

    assert env["OAUTH_ACCESS_TOKEN"] == "fresh-app-token"


def test_valid_cached_app_token_is_reused(
    tmp_path,
    monkeypatch,
):
    """
    A valid cached app token must not trigger another token request.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
        access_token="still-valid-app-token",
        expires_at="9999999999",
    )

    def post_must_not_happen(*args, **kwargs):
        raise AssertionError(
            "Token endpoint was called even though cached app token is valid"
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        post_must_not_happen,
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    assert auth.access_token == "still-valid-app-token"


# ---------------------------------------------------------------------------
# User OAuth regression tests
# ---------------------------------------------------------------------------


def test_user_code_exchange_uses_authorization_code(
    tmp_path,
    monkeypatch,
):
    """
    Existing user OAuth must continue to use authorization_code.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="user",
    )

    captured = {}

    def fake_post(url, *, data, headers, timeout, verify):
        captured["data"] = dict(data)

        return FakeResponse(
            {
                "access_token": "user-token",
                "refresh_token": "user-refresh-token",
                "expires_in": 3600,
                "username": "test.user",
            }
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        fake_post,
    )

    auth = _build_auth(
        env_path,
        auth_type="user",
    )

    auth._exchange_code_for_tokens(
        "authorization-code-123"
    )

    assert (
        captured["data"]["grant_type"]
        == "authorization_code"
    )

    assert (
        captured["data"]["code"]
        == "authorization-code-123"
    )

    assert (
        captured["data"]["redirect_uri"]
        == "urn:ietf:wg:oauth:2.0:oob"
    )

    assert "refresh_token" not in captured["data"]


def test_user_refresh_uses_refresh_token_grant(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="user",
        refresh_token="refresh-123",
    )

    captured = {}

    def fake_post(url, *, data, headers, timeout, verify):
        captured["data"] = dict(data)

        return FakeResponse(
            {
                "access_token": "refreshed-access-token",
                "refresh_token": "replacement-refresh-token",
                "expires_in": 3600,
                "username": "test.user",
            }
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        fake_post,
    )

    auth = _build_auth(
        env_path,
        auth_type="user",
    )

    auth._refresh_access_token()

    assert captured["data"]["grant_type"] == "refresh_token"
    assert captured["data"]["refresh_token"] == "refresh-123"


def test_app_rejects_interactive_login(tmp_path):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    with pytest.raises(
        RuntimeError,
        match="Interactive login",
    ):
        auth._interactive_login()


def test_app_rejects_refresh_token_flow(tmp_path):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
        refresh_token="should-not-be-used",
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    with pytest.raises(
        RuntimeError,
        match="Token refresh",
    ):
        auth._refresh_access_token()


# ---------------------------------------------------------------------------
# Referer behavior
# ---------------------------------------------------------------------------


def test_referer_is_sent_when_configured(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
        referer=REFERER,
    )

    captured = {}

    def fake_post(url, *, data, headers, timeout, verify):
        captured["headers"] = dict(headers)

        return FakeResponse(
            {
                "access_token": "token",
                "expires_in": 3600,
            }
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        fake_post,
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    _ = auth.access_token

    assert captured["headers"] == {
        "Referer": REFERER
    }


def test_no_referer_header_when_unconfigured(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
        referer=None,
    )

    captured = {}

    def fake_post(url, *, data, headers, timeout, verify):
        captured["headers"] = dict(headers)

        return FakeResponse(
            {
                "access_token": "token",
                "expires_in": 3600,
            }
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        fake_post,
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    _ = auth.access_token

    assert captured["headers"] == {}


def test_resolve_app_identity_sends_referer(
    tmp_path,
    monkeypatch,
):
    """
    The portals/self identity request must preserve the app token's referer.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
        referer=REFERER,
        access_token="existing-app-token",
        expires_at="9999999999",
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    fake_store = SimpleNamespace(
        env_path=lambda cid: env_path
    )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "app-test",
            auth,
        ),
    )

    captured = {}

    def fake_get(
        url,
        *,
        params,
        headers,
        timeout,
        verify,
    ):
        captured["url"] = url
        captured["params"] = dict(params)
        captured["headers"] = dict(headers)
        captured["verify"] = verify

        return FakeResponse(
            {
                "appInfo": {
                    "appId": "app-123",
                    "itemId": "item-456",
                    "appTitle": "Egress OAuth",
                    "appOwner": "owner@example.test",
                }
            }
        )

    monkeypatch.setattr(
        oauth_module.requests,
        "get",
        fake_get,
    )

    identity = resolve_identity(
        gis=object(),
        connection="app-test",
    )

    assert identity.auth_type == "app"

    assert captured["url"] == (
        f"{PORTAL}/sharing/rest/portals/self"
    )

    assert captured["headers"] == {
        "Referer": REFERER
    }

    assert captured["params"]["token"] == "existing-app-token"
    assert captured["verify"] is False


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------


def test_resolve_app_identity_uses_appinfo(
    tmp_path,
    monkeypatch,
):
    """
    appOwner is metadata about the credential owner.
    It must never become OAuthIdentity.username.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
        referer=REFERER,
        access_token="existing-app-token",
        expires_at="9999999999",
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    fake_store = SimpleNamespace(
        env_path=lambda cid: env_path
    )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "app-test",
            auth,
        ),
    )

    monkeypatch.setattr(
        oauth_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {
                "appInfo": {
                    "appId": "Z5pGdhvnDdP6SKzA",
                    "itemId": "01f8707ca86a4aa2aa24d3f39b3c5733",
                    "appOwner": "eric.eagle@GISA",
                    "appTitle": "Egress OAuth",
                }
            }
        ),
    )

    identity = resolve_identity(
        gis=object(),
        connection="app-test",
    )

    assert isinstance(identity, OAuthIdentity)

    assert identity.auth_type == "app"
    assert identity.app_id == "Z5pGdhvnDdP6SKzA"
    assert (
        identity.app_item_id
        == "01f8707ca86a4aa2aa24d3f39b3c5733"
    )
    assert identity.app_title == "Egress OAuth"
    assert identity.app_owner == "eric.eagle@GISA"

    # Critical invariant:
    assert identity.username is None

    assert identity.source == "portals/self.appInfo"


def test_resolve_app_identity_requires_app_id(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
        access_token="existing-app-token",
        expires_at="9999999999",
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    fake_store = SimpleNamespace(
        env_path=lambda cid: env_path
    )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "app-test",
            auth,
        ),
    )

    monkeypatch.setattr(
        oauth_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {
                "appInfo": {
                    "appTitle": "Malformed app identity"
                }
            }
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="no appId",
    ):
        resolve_identity(
            gis=object(),
            connection="app-test",
        )


def test_resolve_user_identity_prefers_gis_users_me(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="user",
        access_token="user-token",
        expires_at="9999999999",
    )

    auth = _build_auth(
        env_path,
        auth_type="user",
    )

    fake_store = SimpleNamespace(
        env_path=lambda cid: env_path
    )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "user-test",
            auth,
        ),
    )

    fake_gis = SimpleNamespace(
        users=SimpleNamespace(
            me=SimpleNamespace(
                username="live.user"
            )
        )
    )

    identity = resolve_identity(
        fake_gis,
        connection="user-test",
    )

    assert identity.auth_type == "user"
    assert identity.username == "live.user"
    assert identity.source == "gis.users.me"

    assert identity.app_id is None
    assert identity.app_owner is None


def test_resolve_user_identity_falls_back_to_rest(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="user",
    )

    auth = _build_auth(
        env_path,
        auth_type="user",
    )

    fake_store = SimpleNamespace(
        env_path=lambda cid: env_path
    )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "user-test",
            auth,
        ),
    )

    fake_gis = SimpleNamespace(
        users=SimpleNamespace(
            me=None
        )
    )

    monkeypatch.setattr(
        oauth_module,
        "get_username_via_rest",
        lambda **kwargs: "rest.user",
    )

    identity = resolve_identity(
        fake_gis,
        connection="user-test",
    )

    assert identity.auth_type == "user"
    assert identity.username == "rest.user"
    assert identity.source == "community/self"
    assert identity.warning is not None


def test_resolve_user_identity_falls_back_to_cache(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="user",
        username="cached.user",
    )

    auth = _build_auth(
        env_path,
        auth_type="user",
    )

    fake_store = SimpleNamespace(
        env_path=lambda cid: env_path
    )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "user-test",
            auth,
        ),
    )

    class BrokenUsers:
        @property
        def me(self):
            raise RuntimeError("GIS identity unavailable")

    fake_gis = SimpleNamespace(
        users=BrokenUsers()
    )

    def failed_rest_lookup(**kwargs):
        raise RuntimeError(
            "community/self unavailable"
        )

    monkeypatch.setattr(
        oauth_module,
        "get_username_via_rest",
        failed_rest_lookup,
    )

    identity = resolve_identity(
        fake_gis,
        connection="user-test",
    )

    assert identity.auth_type == "user"
    assert identity.username == "cached.user"
    assert identity.source == "env"
    assert identity.warning is not None


def test_resolve_live_username_rejects_app_identity(
    tmp_path,
    monkeypatch,
):
    """
    The deprecated username resolver must never convert app ownership
    into a human username.
    """

    monkeypatch.setattr(
        oauth_module,
        "resolve_identity",
        lambda *args, **kwargs: OAuthIdentity(
            auth_type="app",
            username=None,
            app_id="app-123",
            app_title="Egress OAuth",
            app_owner="eric.eagle@GISA",
            source="portals/self.appInfo",
        ),
    )

    username, source, warning = resolve_live_username(
        gis=object(),
        connection="app-test",
    )

    assert username is None
    assert source == "portals/self.appInfo"
    assert warning is not None
    assert "application" in warning.lower()


# ---------------------------------------------------------------------------
# Username REST behavior
# ---------------------------------------------------------------------------


def test_get_username_via_rest_rejects_app_auth(
    tmp_path,
    monkeypatch,
):
    """
    /community/self username resolution is user-only.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
        access_token="app-token",
        expires_at="9999999999",
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    fake_store = SimpleNamespace()

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "app-test",
            auth,
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="Username lookup is not valid",
    ):
        get_username_via_rest(
            connection="app-test",
        )


# ---------------------------------------------------------------------------
# Token endpoint error handling
# ---------------------------------------------------------------------------


def test_token_endpoint_http_error_is_raised(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
    )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "error": {
                    "code": 500,
                    "message": "Server failure",
                }
            },
            ok=False,
            status_code=500,
            text="Internal Server Error",
        ),
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    with pytest.raises(
        RuntimeError,
        match="Token endpoint error: 500",
    ):
        _ = auth.access_token


def test_token_endpoint_json_error_is_raised(
    tmp_path,
    monkeypatch,
):
    """
    ArcGIS may return a successful HTTP response containing an OAuth error.
    That must still fail authentication.
    """

    env_path = _write_env(
        tmp_path,
        auth_type="app",
    )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "error": {
                    "code": 498,
                    "message": "Invalid token.",
                    "details": [
                        "Error validating token: Invalid Referer."
                    ],
                }
            },
            ok=True,
            status_code=200,
        ),
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    with pytest.raises(
        RuntimeError,
        match="Token endpoint returned error",
    ):
        _ = auth.access_token


def test_failed_app_token_request_does_not_persist_new_state(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
        access_token="old-expired-token",
        expires_at="1",
    )

    monkeypatch.setattr(
        oauth_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {
                "error": {
                    "message": "Invalid client credentials"
                }
            },
            ok=True,
        ),
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    with pytest.raises(RuntimeError):
        _ = auth.access_token

    env = parse_env_file(env_path)

    assert env["OAUTH_ACCESS_TOKEN"] == "old-expired-token"


# ---------------------------------------------------------------------------
# get_gis behavior
# ---------------------------------------------------------------------------


def _install_fake_arcgis(monkeypatch, constructor):
    """
    Install a tiny fake arcgis.gis module so unit tests do not require
    the optional ArcGIS Python API package.
    """

    arcgis_module = types.ModuleType("arcgis")
    gis_module = types.ModuleType("arcgis.gis")

    gis_module.GIS = constructor
    arcgis_module.gis = gis_module

    monkeypatch.setitem(
        sys.modules,
        "arcgis",
        arcgis_module,
    )

    monkeypatch.setitem(
        sys.modules,
        "arcgis.gis",
        gis_module,
    )


def test_get_gis_app_passes_token_referer_and_ssl(
    tmp_path,
    monkeypatch,
):
    env_path = _write_env(
        tmp_path,
        auth_type="app",
        referer=REFERER,
        access_token="app-token",
        expires_at="9999999999",
    )

    auth = _build_auth(
        env_path,
        auth_type="app",
    )

    touched = []
    captured = {}

    fake_store = SimpleNamespace(
        touch=lambda cid: touched.append(cid)
    )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        lambda **kwargs: (
            fake_store,
            "app-test",
            auth,
        ),
    )

    def rotation_must_not_happen(**kwargs):
        raise AssertionError(
            "refresh-token rotation was attempted for app auth"
        )

    monkeypatch.setattr(
        oauth_module,
        "_rotate_refresh_token_if_needed",
        rotation_must_not_happen,
    )

    def fake_gis_constructor(
        portal_url,
        *,
        token,
        verify_cert,
        **kwargs,
    ):
        captured["portal_url"] = portal_url
        captured["token"] = token
        captured["verify_cert"] = verify_cert
        captured["kwargs"] = kwargs

        return SimpleNamespace(
            portal_url=portal_url
        )

    _install_fake_arcgis(
        monkeypatch,
        fake_gis_constructor,
    )

    gis = get_gis(
        connection="app-test"
    )

    assert gis.portal_url == PORTAL

    assert captured["token"] == "app-token"
    assert captured["verify_cert"] is False
    assert captured["kwargs"]["referer"] == REFERER

    assert touched == ["app-test"]


def test_get_gis_user_rotates_then_reloads_auth(
    tmp_path,
    monkeypatch,
):
    first_env = _write_env(
        tmp_path,
        auth_type="user",
        access_token="old-token",
        expires_at="9999999999",
    )

    first_auth = _build_auth(
        first_env,
        auth_type="user",
    )

    second_auth = _build_auth(
        first_env,
        auth_type="user",
    )

    second_auth._access_token = "rotated-token"

    fake_store = SimpleNamespace(
        touch=lambda cid: None
    )

    calls = []

    def fake_loader(**kwargs):
        calls.append(kwargs)

        if len(calls) == 1:
            return (
                fake_store,
                "user-test",
                first_auth,
            )

        return (
            fake_store,
            "user-test",
            second_auth,
        )

    monkeypatch.setattr(
        oauth_module,
        "_load_auth_for_connection",
        fake_loader,
    )

    rotation_calls = []

    monkeypatch.setattr(
        oauth_module,
        "_rotate_refresh_token_if_needed",
        lambda **kwargs: rotation_calls.append(
            kwargs
        ),
    )

    captured = {}

    def fake_gis_constructor(
        portal_url,
        *,
        token,
        verify_cert,
        **kwargs,
    ):
        captured["token"] = token

        return SimpleNamespace()

    _install_fake_arcgis(
        monkeypatch,
        fake_gis_constructor,
    )

    get_gis(
        connection="user-test"
    )

    assert len(rotation_calls) == 1

    # Initial load + reload after rotation
    assert len(calls) == 2

    assert captured["token"] == "rotated-token"