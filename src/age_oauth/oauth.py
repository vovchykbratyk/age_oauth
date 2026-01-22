# age_oauth/oauth.py
from __future__ import annotations

import os
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

from .envfile import load_env, read_env, set_env_key
from .connections import ConnectionStore

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

    # treat as path
    if os.path.exists(env_verify):
        return env_verify
    raise ValueError(
        f"OAUTH_VERIFY_SSL set to {env_verify!r} but is not a boolean or valid path value"
    )


@dataclass
class OAuthConfig:
    portal_url: str
    client_id: str
    client_secret: str
    env_path: str
    redirect_uri: str = "urn:ietf:wg:oauth:2.0:oob"
    scope: str = "portal:user:read,portal:item:read,portal:group:read"
    verify_ssl: bool = True


class AGEOAuth:
    """
    ArcGIS Enterprise OAuth helper bound to a specific connection profile (.env file).
    """

    def __init__(self, config: OAuthConfig):
        if not config.env_path:
            raise ValueError("OAuthConfig.env_path is required")

        self.config = config
        self.env_path = str(Path(config.env_path).expanduser())

        # Load env for this profile into os.environ (simple + consistent with current approach)
        load_env(self.env_path)

        # Verify setting: bool or path
        self.verify_ssl = _coerce_verify_ssl(os.getenv("OAUTH_VERIFY_SSL"), default=config.verify_ssl)

        # populate from env (with config defaults)
        self.portal_url = os.getenv("PORTAL_URL", config.portal_url).rstrip("/")
        self.client_id = os.getenv("OAUTH_CLIENT_ID", config.client_id)
        self.client_secret = os.getenv("OAUTH_CLIENT_SECRET", config.client_secret)
        self.redirect_uri = os.getenv("OAUTH_REDIRECT_URI", config.redirect_uri)
        self.scope = os.getenv("OAUTH_SCOPE", config.scope)

        # token state from env (won't be there on first run)
        self._access_token = os.getenv("OAUTH_ACCESS_TOKEN", "")
        self._refresh_token = os.getenv("OAUTH_REFRESH_TOKEN", "")
        self._expires_at = float(os.getenv("OAUTH_TOKEN_EXPIRES_AT") or 0)
        self._username = os.getenv("OAUTH_USERNAME", "")

        self.authorize_url = f"{self.portal_url}/sharing/rest/oauth2/authorize"
        self.token_url = f"{self.portal_url}/sharing/rest/oauth2/token"

    @property
    def access_token(self) -> str:
        if not self._access_token or self.is_expired():
            self.refresh_or_login()
        return self._access_token

    @property
    def portal(self) -> str:
        return self.portal_url

    def is_expired(self, skew_seconds: int = 60) -> bool:
        return time.time() >= (self._expires_at - skew_seconds)

    def refresh_or_login(self) -> None:
        if self._refresh_token:
            try:
                self._refresh_access_token()
                return
            except Exception as ex:
                log.warning("Refresh failed: %r – falling back to interactive login.", ex)
        self._interactive_login()

    def _interactive_login(self) -> None:
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
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        self._request_token(data)

    def _refresh_access_token(self) -> None:
        if not self._refresh_token:
            raise RuntimeError("No refresh_token available for refresh.")
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
        }
        print("Refreshing access token using refresh_token...")
        self._request_token(data)

    def _request_token(self, data: Dict[str, str]) -> None:
        resp = requests.post(self.token_url, data=data, timeout=30, verify=self.verify_ssl)
        if not resp.ok:
            raise RuntimeError(f"Token endpoint error: {resp.status_code} {resp.text}")

        payload = resp.json()
        self._access_token = payload["access_token"]
        expires_in = float(payload.get("expires_in", 3600))
        self._expires_at = time.time() + expires_in

        if "refresh_token" in payload:
            self._refresh_token = payload["refresh_token"]
        if "username" in payload:
            self._username = payload["username"]
        if "scope" in payload:
            self.scope = payload["scope"]

        expires_in_readable = _to_readable_time(expires_in)
        print(f"New access_token acquired! Expires in: {expires_in_readable}")
        if self._username:
            print(f"Token is for user: {self._username}")

        self._persist()

    def _persist(self) -> None:
        """
        Persist everything into this profile's env file.
        """
        env_path = self.env_path

        def save(key: str, value: object) -> None:
            set_env_key(env_path, key, str(value))

        # core (re-write, harmless)
        save("PORTAL_URL", self.portal_url)
        save("OAUTH_CLIENT_ID", self.client_id)
        save("OAUTH_CLIENT_SECRET", self.client_secret)

        env_verify = os.getenv("OAUTH_VERIFY_SSL", "").strip()
        if env_verify:
            save("OAUTH_VERIFY_SSL", env_verify)

        # token-ish
        save("OAUTH_REDIRECT_URI", self.redirect_uri)
        save("OAUTH_SCOPE", self.scope)
        save("OAUTH_ACCESS_TOKEN", self._access_token)
        save("OAUTH_REFRESH_TOKEN", self._refresh_token)
        save("OAUTH_TOKEN_EXPIRES_AT", self._expires_at)  # epoch
        iso_expiration = datetime.fromtimestamp(self._expires_at, tz=timezone.utc).isoformat()
        save("OAUTH_TOKEN_EXPIRES_AT_UTC", iso_expiration)
        if self._username:
            save("OAUTH_USERNAME", self._username)


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

    store = ConnectionStore()
    cid = store.resolve(connection=connection, connection_id=connection_id)

    # Ensure env file exists + has required core keys; prompt if allowed.
    if prompt_if_missing:
        store.ensure_ready(cid, prompt=True)
    else:
        store.ensure_ready(cid, prompt=False)

    env_file = store.env_path(cid)

    # quick read from env file, build OAuthConfig from those vals without modding os.environ
    env = read_env(env_file)

    portal_url = (env.get("PORTAL_URL") or "").rstrip("/")
    client_id = env.get("OAUTH_CLIENT_ID") or ""
    client_secret = env.get("OAUTH_CLIENT_SECRET") or ""
    if not portal_url or not client_id or not client_secret:
        raise RuntimeError(f"Core OAuth settings incomplete for connection: {cid}")

    cfg = OAuthConfig(
        portal_url=portal_url,
        client_id=client_id,
        client_secret=client_secret,
        env_path=str(env_file),
    )
    auth = AGEOAuth(cfg)

    store.touch(cid)

    # GIS SSL handling: verify_cert bool + ca_bundles path when needed
    gis_kwargs = {}
    v = auth.verify_ssl
    if isinstance(v, bool):
        gis_verify = v
    else:
        ca_path = str(Path(v).expanduser())
        gis_verify = True
        gis_kwargs["ca_bundles"] = ca_path

    return GIS(auth.portal_url, token=auth.access_token, verify_cert=gis_verify, **gis_kwargs)
