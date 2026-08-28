# age_oauth/oauth.py
from __future__ import annotations

import time
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict
from urllib.parse import urlencode

import requests
import webbrowser

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .envfile import parse_env_file, set_env_key, set_env_keys
from .connections import ConnectionStore, _normalize_auth_type

log = logging.getLogger("age_oauth")


def _to_readable_time(total_seconds: float) -> str:
    """
    reports timespan in human readable format ("H:MM:SS" or "X Days, H:MM:SS")
    """
    try:
        if total_seconds < 0:
            return f"-{_to_readable_time(-total_seconds)}"
        return str(timedelta(seconds=float(total_seconds)))
    except (OverflowError, TypeError, ValueError) as e:
        return f"Input error {total_seconds!r}: {e}"


def _coerce_verify_ssl(env_value: str | None, default: bool = True) -> bool | str:
    """
    Coerce OAUTH_VERIFY_SSL into:
      - True/False
      - or a filesystem path (string) to a CA bundle/cert
    """
    env_verify = (env_value or "").strip()
    if not env_verify:
        return bool(default)

    v = env_verify.lower()
    if v in ("false", "0", "no", "off"):
        return False
    if v in ("true", "1", "yes", "on"):
        return True

    p = Path(env_verify).expanduser()

    if p.exists():
        return str(p)

    raise ValueError(
        f"OAUTH_VERIFY_SSL set to {env_verify!r} "
        f"but is not boolean or a valid path value"
    )


def _rotate_refresh_token_if_needed(
    *,
    connection: str | None = None,
    connection_id: str | None = None,
    max_age_days: int = 3,
) -> None:
    """
    best effort non-interactive rotation of refresh_token
    intention is to keep long running tasks alive
    """
    try:
        from .tokens import maybe_rotate_refresh_token

        result = maybe_rotate_refresh_token(
            connection=connection,
            connection_id=connection_id,
            max_age_days=max_age_days,
        )

        if result.rotated:
            log.info(
                "Refresh token rotated for connection=%s portal=%s",
                result.connection_id,
                result.portal_url
            )
        else:
            log.info(
                "Refresh token rotation not needed for connection=%s: %s",
                result.connection_id,
                result.reason,
            )
    except RuntimeError as ex:
        # handle normal edge cases here
        # - no refresh token yet because user hasn't logged in,
        # - connection isn't ready,
        # - portal rejected the exchange for some reason
        log.warning("Refresh-token rotation skipped: %r", ex)

    except Exception as ex:
        # just some defensive architecture here, avoid a botched rotation taking down get_gis()
        log.warning("Unexpected refresh-token rotation failure: %r", ex)

@dataclass
class OAuthConfig:
    portal_url: str
    client_id: str
    client_secret: str
    env_path: str
    auth_type: str = "user"
    redirect_uri: str = "urn:ietf:wg:oauth:2.0:oob"
    scope: str = "portal:user:read,portal:item:read,portal:group:read"
    referer: str | None = None
    verify_ssl: bool | str = False


@dataclass
class OAuthIdentity:
    auth_type: str

    username: str | None = None

    app_id: str | None = None
    app_item_id: str | None = None
    app_title: str | None = None
    app_owner: str | None = None

    source: str | None = None
    warning: str | None = None






class AGEOAuth:
    """
    ArcGIS Enterprise OAuth helper bound to a specific connection profile (.env file).
    """

    def __init__(self, config: OAuthConfig):
        if not config.env_path:
            raise ValueError("OAuthConfig.env_path is required")

        self.config = config
        self.env_path = str(Path(config.env_path).expanduser())

        self.env = parse_env_file(self.env_path)
        env = self.env
        
        # verify can be bool or path to custom CA
        self.verify_ssl = _coerce_verify_ssl(env.get("OAUTH_VERIFY_SSL"), default=config.verify_ssl)

        verify_raw = (env.get("OAUTH_VERIFY_SSL") or "").strip()

        if not verify_raw:
            if isinstance(self.verify_ssl, bool):
                verify_persisted = "true" if self.verify_ssl else "false"
            else:
                verify_persisted = str(Path(self.verify_ssl).expanduser())

            set_env_key(
                self.env_path,
                "OAUTH_VERIFY_SSL",
                verify_persisted,
            )
            self.env["OAUTH_VERIFY_SSL"] = verify_persisted

        # config defaults
        self.portal_url = (env.get("PORTAL_URL") or config.portal_url).rstrip("/")
        self.client_id = env.get("OAUTH_CLIENT_ID") or config.client_id
        self.client_secret = env.get("OAUTH_CLIENT_SECRET") or config.client_secret
        self.redirect_uri = env.get("OAUTH_REDIRECT_URI") or config.redirect_uri
        self.scope = env.get("OAUTH_SCOPE") or config.scope
        self.auth_type = _normalize_auth_type(env.get("OAUTH_AUTH_TYPE") or config.auth_type)
        self.referer = (env.get("OAUTH_REFERER") or config.referer or "").strip() or None

        # token state (won't be there on first run)
        self._access_token = env.get("OAUTH_ACCESS_TOKEN", "")
        self._refresh_token = env.get("OAUTH_REFRESH_TOKEN", "")
        self._expires_at = float(env.get("OAUTH_TOKEN_EXPIRES_AT") or 0)
        self._username = env.get("OAUTH_USERNAME", "")
        self._refresh_token_rotated_at = (
            env.get("OAUTH_REFRESH_TOKEN_ROTATED_AT") or ""
        )
        self._refresh_token_rotated_at_utc = (
            env.get("OAUTH_REFRESH_TOKEN_ROTATED_AT_UTC") or ""
        )

        self.authorize_url = f"{self.portal_url}/sharing/rest/oauth2/authorize"
        self.token_url = f"{self.portal_url}/sharing/rest/oauth2/token"

        

    @property
    def access_token(self) -> str:
        if not self._access_token or self.is_expired():
            if self.auth_type == "app":
                self._request_client_credentials_token()
            else:
                self.refresh_or_login()

        return self._access_token

    @property
    def portal(self) -> str:
        return self.portal_url

    def is_expired(self, skew_seconds: int = 60) -> bool:
        return time.time() >= (self._expires_at - skew_seconds)

    def refresh_or_login(self) -> None:
        if self.auth_type != "user":
            self._request_client_credentials_token()
            return
        if self._refresh_token:
            try:
                self._refresh_access_token()
                return
            except Exception as ex:
                log.warning("Refresh failed: %r – falling back to interactive login.", ex)
        self._interactive_login()

    def _interactive_login(self) -> None:
        if self.auth_type != "user":
            raise RuntimeError("Interactive login is only valid for user-authenticated connections")
        
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
        }
        url = f"{self.authorize_url}?{urlencode(params)}"

        print("Opening browser for ArcGIS Enterprise OAuth sign-in...")
        print(f"If the browser does not open, copy/paste this URL manually:\n{url}\n")
        webbrowser.open(url)

        print("After signing in, your portal will show an authorization code.")
        code = input("Paste the authorization code here: ").strip()
        if not code:
            raise RuntimeError("No authorization code entered.")

        print("Exchanging code for tokens...")
        self._exchange_code_for_tokens(code)

    def _exchange_code_for_tokens(self, code: str) -> None:
        if self.auth_type != "user":
            raise RuntimeError("Interactive login is only valid for user-authenticated connections")
        
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        self._request_token(data)

    def _refresh_access_token(self) -> None:
        if self.auth_type != "user":
            raise RuntimeError("Token refresh is only valid for user-authenticated connections")

        if not self._refresh_token:
            raise RuntimeError("No refresh_token available for refresh.")
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "redirect_uri": self.redirect_uri,
        }
        print("Refreshing access token using refresh_token...")
        self._request_token(data)

    def _request_client_credentials_token(self) -> None:
        print("Authenticating application using client credentials...")

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }

        self._request_token(data)

    def _request_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}

        if self.referer:
            headers["Referer"] = self.referer

        return headers

    def _request_token(self, data: Dict[str, str]) -> None:
        data = dict(data)
        data["f"] = "json"
        resp = requests.post(
            self.token_url,
            data=data,
            headers=self._request_headers(),
            timeout=30,
            verify=self.verify_ssl,
        )

        if not resp.ok:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise RuntimeError(f"Token endpoint error: {resp.status_code} {detail}")

        payload = resp.json()
        if "error" in payload:
            raise RuntimeError(f"Token endpoint returned error: {payload['error']}")
        
        self._access_token = payload["access_token"]
        expires_in = float(payload.get("expires_in", 3600))
        self._expires_at = time.time() + expires_in

        if self.auth_type == "user" and "refresh_token" in payload:
            self._refresh_token = payload["refresh_token"]

            now_epoch = time.time()
            self._refresh_token_rotated_at = str(now_epoch)
            self._refresh_token_rotated_at_utc = datetime.fromtimestamp(
                now_epoch,
                tz=timezone.utc,
            ).isoformat()

        if self.auth_type == "user":
            self._username = payload.get("username", "") or ""

            if not self._username:
                try:
                    url = f"{self.portal_url}/sharing/rest/community/self"

                    params = {
                        "f": "json",
                        "token": self._access_token,
                    }

                    who = requests.get(
                        url,
                        params=params,
                        headers=self._request_headers(),
                        timeout=30,
                        verify=self.verify_ssl,
                    )

                    if who.ok:
                        info = who.json()
                        self._username = (info.get("username") or "").strip()

                except Exception as ex:
                    log.warning("Unable to backfill username from community/self: %r", ex)

        else:   # app auth
            self._username = ""
            self._refresh_token = ""
                    
        if "scope" in payload:
            self.scope = payload["scope"]

        expires_in_readable = _to_readable_time(expires_in)
        print(f"New access_token acquired! Expires in: {expires_in_readable}")
        if self._username:
            print(f"Token is for user: {self._username}")

        self._persist()

    def _persist(self) -> None:
        """
        persist the current connection state into this profile's env
        """
        v = self.verify_ssl
        if isinstance(v, bool):
            verify_ssl = "true" if v else "false"
        else:
            verify_ssl = str(Path(v).expanduser())  # in case of custom CA cert

        values = {
            "PORTAL_URL": self.portal_url,
            "OAUTH_CLIENT_ID": self.client_id,
            "OAUTH_CLIENT_SECRET": self.client_secret,
            "OAUTH_AUTH_TYPE": self.auth_type,
            "OAUTH_REFERER": self.referer or "",
            "OAUTH_VERIFY_SSL": verify_ssl,
            "OAUTH_REDIRECT_URI": self.redirect_uri,
            "OAUTH_SCOPE": self.scope,
            "OAUTH_ACCESS_TOKEN": self._access_token,
            "OAUTH_TOKEN_EXPIRES_AT": str(self._expires_at),
            "OAUTH_TOKEN_EXPIRES_AT_UTC": datetime.fromtimestamp(
                self._expires_at,
                tz=timezone.utc,
            ).isoformat(),
        }

        if self.auth_type == "app":
            values["OAUTH_REFRESH_TOKEN"] = ""
            values["OAUTH_REFRESH_TOKEN_ROTATED_AT"] = ""
            values["OAUTH_REFRESH_TOKEN_ROTATED_AT_UTC"] = ""
            values["OAUTH_USERNAME"] = ""
        else:
            values["OAUTH_REFRESH_TOKEN"] = self._refresh_token
            values["OAUTH_REFRESH_TOKEN_ROTATED_AT"] = self._refresh_token_rotated_at
            values["OAUTH_REFRESH_TOKEN_ROTATED_AT_UTC"] = self._refresh_token_rotated_at_utc
            values["OAUTH_USERNAME"] = self._username or ""

        set_env_keys(self.env_path, values)

        self.env.update(values)


def _load_auth_for_connection(
    *,
    connection: str | None = None,
    connection_id: str | None = None,
    prompt_if_missing: bool = False
) -> tuple[ConnectionStore, str, AGEOAuth]:
    """
    Resolve a saved connection profile and construct an AGEOAuth instance

    returns (store, connection_id, auth)

    this helper only loads and validates connection config, it does not rotate tokens or anything else
    """
    store = ConnectionStore()

    cid = store.resolve(
        connection=connection,
        connection_id=connection_id,
    )

    store.ensure_ready(
        cid,
        prompt=prompt_if_missing,
    )

    env_file = store.env_path(cid)
    env = parse_env_file(env_file)

    portal_url = (env.get("PORTAL_URL") or "").rstrip("/")
    client_id = (env.get("OAUTH_CLIENT_ID") or "").strip()
    client_secret = (env.get("OAUTH_CLIENT_SECRET") or "").strip()
    auth_type = _normalize_auth_type(env.get("OAUTH_AUTH_TYPE"))

    missing = []

    if not portal_url:
        missing.append("PORTAL_URL")

    if not client_id:
        missing.append("OAUTH_CLIENT_ID")

    if not client_secret:
        missing.append("OAUTH_CLIENT_SECRET")

    if missing:
        raise RuntimeError(
            f"Core OAuth settings incomplete for connection {cid}: "
            f"{', '.join(missing)}"
        )

    cfg = OAuthConfig(
        portal_url=portal_url,
        client_id=client_id,
        client_secret=client_secret,
        env_path=str(env_file),
        auth_type=auth_type,
    )

    auth = AGEOAuth(cfg)

    return store, cid, auth


def resolve_identity(
    gis,
    *,
    connection: str | None = None,
    connection_id: str | None = None,
) -> OAuthIdentity:
    """
    Resolve the authenticated principal for the selected connection.

    User-authenticated connections:
      1. Try gis.users.me
      2. Fall back to /community/self
      3. Fall back to cached OAUTH_USERNAME

    App-authenticated connections:
      1. Query /portals/self
      2. Read appInfo
      3. Return application identity information

    appOwner identifies the owner of the OAuth application item.
    It is NOT treated as the authenticated username.
    """

    store, cid, auth = _load_auth_for_connection(
        connection=connection,
        connection_id=connection_id,
        prompt_if_missing=False,
    )

    env = parse_env_file(store.env_path(cid))


    # App authentication
    if auth.auth_type == "app":
        url = f"{auth.portal_url}/sharing/rest/portals/self"

        params = {
            "f": "json",
            "token": auth.access_token,
        }

        resp = requests.get(
            url,
            params=params,
            headers=auth._request_headers(),
            timeout=30,
            verify=auth.verify_ssl,
        )

        if not resp.ok:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text

            raise RuntimeError(
                f"portals/self lookup failed: "
                f"{resp.status_code} {detail}"
            )

        payload = resp.json()

        

        if "error" in payload:
            raise RuntimeError(
                f"portals/self returned error: {payload['error']}"
            )

        app_info = payload.get("appInfo") or {}

        if not app_info:
            raise RuntimeError(
                "Application-authenticated connection did not return "
                "appInfo from portals/self."
            )

        app_id = (app_info.get("appId") or "").strip()

        if not app_id:
            raise RuntimeError(
                "Application-authenticated response contained "
                "appInfo but no appId."
            )

        if payload.get("user"):
            log.warning(
                "Application-authenticated response unexpectedly "
                "included a user object."
            )

        return OAuthIdentity(
            auth_type="app",
            app_id=app_id,
            app_item_id=(app_info.get("itemId") or "").strip() or None,
            app_title=(app_info.get("appTitle") or "").strip() or None,
            app_owner=(app_info.get("appOwner") or "").strip() or None,
            source="portals/self.appInfo",
        )

    # User auth
    # try... ArcGIS Python API identity
    try:
        me = gis.users.me

        username = (
            getattr(me, "username", None) or ""
        ).strip()

        if username:
            return OAuthIdentity(
                auth_type="user",
                username=username,
                source="gis.users.me",
            )

    except Exception as ex:
        log.warning(
            "gis.users.me lookup failed: %r",
            ex,
        )

    # or.. direct REST call
    try:
        username = get_username_via_rest(
            connection=connection,
            connection_id=connection_id,
            prompt_if_missing=False,
        )

        if username:
            return OAuthIdentity(
                auth_type="user",
                username=username,
                source="community/self",
                warning=(
                    "ArcGIS Python API did not populate "
                    "gis.users.me.username; identity was resolved "
                    "using community/self."
                ),
            )

    except Exception as ex:
        log.warning(
            "community/self lookup failed: %r",
            ex,
        )

    # or, lastly, cached username
    username = (
        env.get("OAUTH_USERNAME") or ""
    ).strip()

    if username:
        return OAuthIdentity(
            auth_type="user",
            username=username,
            source="env",
            warning=(
                "Live identity lookup failed. "
                "Using cached OAUTH_USERNAME."
            ),
        )

    return OAuthIdentity(
        auth_type="user",
        source="unknown",
        warning=(
            "Unable to determine authenticated user from "
            "gis.users.me, community/self, or cached profile."
        ),
    )


def resolve_live_username(
    gis,
    *,
    connection: str | None = None,
    connection_id: str | None = None,
) -> tuple[str | None, str, str | None]:
    """
    Backward-compatible user identity resolver.

    Deprecated: use resolve_identity() for new code.
    """

    identity = resolve_identity(
        gis,
        connection=connection,
        connection_id=connection_id,
    )

    if identity.auth_type != "user":
        return (
            None,
            identity.source or "app",
            (
                "Connection is authenticated as an application, "
                "not as a user."
            ),
        )

    return (
        identity.username,
        identity.source or "unknown",
        identity.warning,
    )


def get_username_via_rest(
    *,
    connection: str | None = None,
    connection_id: str | None = None,
    prompt_if_missing: bool = True,
) -> str | None:
    """
    Resolve the saved connection, make sure a live access token exists,
    and get the current user from portal via REST (outside API wrapper)
    """

    
    _, _, auth = _load_auth_for_connection(
        connection=connection,
        connection_id=connection_id,
        prompt_if_missing=prompt_if_missing,
    )

    if auth.auth_type != "user":
        raise RuntimeError("Username lookup is not valid for application authenticated connections")

    # pester the request_token for rotation if it needs it
    _rotate_refresh_token_if_needed(
        connection=connection,
        connection_id=connection_id,
        max_age_days=3,
    )

    # reread profile because rotation may have updated refresh/access token state!
    _, _, auth = _load_auth_for_connection(
        connection=connection,
        connection_id=connection_id,
        prompt_if_missing=False,
    )

    url = f"{auth.portal_url}/sharing/rest/community/self"
    params = {
        "f": "json",
        "token": auth.access_token,
    }

    resp = requests.get(
        url,
        params=params,
        headers=auth._request_headers(),
        timeout=30,
        verify=auth.verify_ssl,
    )
    if not resp.ok:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise RuntimeError(f"community/self lookup failed: {resp.status_code} {detail}")

    payload = resp.json()
    if "error" in payload:
        raise RuntimeError(f"community/self returned error: {payload['error']}")

    username = (payload.get("username") or "").strip()
    return username or None


def get_gis(
    *,
    connection: str | None = None,
    connection_id: str | None = None,
    prompt_if_missing: bool = True,
):
    """
    Resolve a saved connection profile, ensure required settings exist,
    negotiate/refresh token, and return arcgis.gis.GIS.

    If prompt_if_missing=True, missing core settings will be prompted for.
    """
    from arcgis.gis import GIS

    store, cid, auth = _load_auth_for_connection(
        connection=connection,
        connection_id=connection_id,
        prompt_if_missing=prompt_if_missing,
    )

    if auth.auth_type == "user":
        _rotate_refresh_token_if_needed(
            connection=connection,
            connection_id=connection_id,
            max_age_days=3,
        )
        # reread profile because rotation may have updated refresh/access token state!
        _, _, auth = _load_auth_for_connection(
            connection=connection,
            connection_id=connection_id,
            prompt_if_missing=False,
        )

    # GIS SSL handling: verify_cert bool + ca_bundles path when needed
    gis_kwargs = {}

    v = auth.verify_ssl

    if isinstance(v, bool):
        gis_verify = v
    else:
        ca_path = str(Path(v).expanduser())
        gis_verify = True
        gis_kwargs["ca_bundles"] = ca_path

    # preserve token-bound HTTP referer
    if auth.referer:
        gis_kwargs["referer"] = auth.referer

    gis = GIS(
        auth.portal_url,
        token=auth.access_token,
        verify_cert=gis_verify,
        **gis_kwargs
    )

    store.touch(cid)

    return gis
