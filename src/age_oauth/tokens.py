from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import requests

from .connections import ConnectionStore
from .envfile import parse_env_file, set_env_key
from .oauth import _coerce_verify_ssl

log = logging.getLogger("age_oauth")


def _utc_now_epoch() -> float:
    return time.time()


def _to_readable_time(total_seconds: float) -> str:
    try:
        if total_seconds < 0:
            return f"-{_to_readable_time(-total_seconds)}"
        return str(timedelta(seconds=float(total_seconds)))
    except (OverflowError, TypeError, ValueError) as e:
        return f"Input error {total_seconds!r}: {e}"
    

@dataclass(frozen=True)
class RefreshTokenRotationResult:
    connection_id: str
    portal_url: str
    attempted: bool
    rotated: bool
    reason: str
    refresh_token_age_seconds: Optional[float] = None
    rotated_at_epoch: Optional[float] = None
    username: Optional[str] = None


def _load_connection_env(
    *,
    connection: str | None = None,
    connection_id: str | None = None,
) -> tuple[ConnectionStore, str, Path, dict[str, str]]:
    
    store = ConnectionStore()
    cid = store.resolve(connection=connection, connection_id=connection_id)
    store.ensure_ready(cid, prompt=False)

    env_path = store.env_path(cid)
    env = parse_env_file(env_path)

    return store, cid, env_path, env


def _save_env_key(env_path: Path, key: str, value: object) -> None:
    set_env_key(str(env_path), key, str(value))


def _get_refresh_token_age_seconds(env: dict[str, str]) -> Optional[float]:
    """
    check OAUTH_REFRESH_TOKEN_ROTATED_AT - if timestamp missing, return None
    and let caller decide whether to rotate
    """
    raw = (env.get("OAUTH_REFRESH_TOKEN_ROTATED_AT") or "").strip()
    if not raw:
        return None
    
    try:
        rotated_at = float(raw)
    except ValueError:
        return None
    
    return max(0.0, _utc_now_epoch() - rotated_at)


def _exchange_refresh_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    redirect_uri: str,
    verify_ssl: bool | str,
) -> dict:
    
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "exchange_refresh_token",
        "refresh_token": refresh_token,
        "redirect_uri": redirect_uri,
        "f": "json",
    }

    resp = requests.post(token_url, data=data, timeout=30, verify=verify_ssl)

    if not resp.ok:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise RuntimeError(f"Token endpoint error: {resp.status_code} {detail}")
    
    payload = resp.json()

    if "error" in payload:
        raise RuntimeError(f"Token endpoint returned error: {payload['error']}")
    
    return payload


def maybe_rotate_refresh_token(
    *,
    connection: str | None = None,
    connection_id: str | None = None,
    max_age_days: int = 3,
) -> RefreshTokenRotationResult:
    """
    non interactively rotate stored refresh token if it's older than max_age_days.

    logic:
    if no refresh token exists, raise
    if refresh token age is unknown, try to rotate it once and store the timestamp on success
    if token is younger than the threshold, leave it alone
    if token is old enough, rotate it for a new one and store it
    """

    store, cid, env_path, env = _load_connection_env(
        connection=connection,
        connection_id=connection_id,
    )

    portal_url = (env.get("PORTAL_URL") or "").rstrip("/")
    client_id = (env.get("OAUTH_CLIENT_ID") or "").strip()
    client_secret = (env.get("OAUTH_CLIENT_SECRET") or "").strip()
    redirect_uri = (env.get("OAUTH_REDIRECT_URI") or "urn:ietf:wg:oauth:2.0:oob").strip()
    refresh_token = (env.get("OAUTH_REFRESH_TOKEN") or "").strip()
    username = (env.get("OAUTH_USERNAME") or "").strip() or None

    if not portal_url or not client_id or not client_secret:
        raise RuntimeError(f"Core OAuth settings incomplete for connection: {cid}")
    
    if not refresh_token:
        raise RuntimeError(f"No stored refresh token exists for connection {cid}. Run 'age-oauth login' first.")
    
    verify_ssl = _coerce_verify_ssl(env.get("OAUTH_VERIFY_SSL"), default=False)
    token_url = f"{portal_url}/sharing/rest/oauth2/token"

    age_seconds = _get_refresh_token_age_seconds(env)
    threshold_seconds = max_age_days * 24 * 60 * 60

    if age_seconds is not None and age_seconds < threshold_seconds:
        remaining = threshold_seconds - age_seconds
        return RefreshTokenRotationResult(
            connection_id=cid,
            portal_url=portal_url,
            attempted=False,
            rotated=False,
            reason=(
                f"Refresh token is not old enough to rotate yet "
                f"(age={_to_readable_time(age_seconds)}), "
                f"threshold={_to_readable_time(threshold_seconds)}, "
                f"remaining={_to_readable_time(remaining)})."
            ),
            refresh_token_age_seconds=age_seconds,
            username=username,
        )
    
    log.info(
        "Attempting refresh-token rotation for connection=%s portal=%s age_seconds=%r threshold_seconds=%s",
        cid,
        portal_url,
        age_seconds,
        threshold_seconds,
    )

    payload = _exchange_refresh_token(
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
        redirect_uri=redirect_uri,
        verify_ssl=verify_ssl,
    )

    new_refresh_token = (payload.get("refresh_token") or "").strip()
    if not new_refresh_token:
        raise RuntimeError("Token exchange succeeded but no refresh_token was returned")
    
    now_epoch = _utc_now_epoch()
    now_iso = datetime.fromtimestamp(now_epoch, tz=timezone.utc).isoformat()

    _save_env_key(env_path, "OAUTH_REFRESH_TOKEN", new_refresh_token)
    _save_env_key(env_path, "OAUTH_REFRESH_TOKEN_ROTATED_AT", now_epoch)
    _save_env_key(env_path, "OAUTH_REFRESH_TOKEN_ROTATED_AT_UTC", now_iso)

    # capture any other related token metadata the endpoint returns
    if "access_token" in payload:
        access_token = str(payload["access_token"])
        _save_env_key(env_path, "OAUTH_ACCESS_TOKEN", access_token)

        expires_in = float(payload.get("expires_in", 3600))
        expires_at = now_epoch + expires_in
        expires_at_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

        _save_env_key(env_path, "OAUTH_TOKEN_EXPIRES_AT", expires_at)
        _save_env_key(env_path, "OAUTH_TOKEN_EXPIRES_AT_UTC", expires_at_iso)

    if "username" in payload and str(payload["username"]).strip():
        _save_env_key(env_path, "OAUTH_USERNAME", str(payload["username"]))
        username = str(payload["username"]).strip()

    if "scope" in payload and str(payload["scope"]).strip():
        _save_env_key(env_path, "OAUTH_SCOPE", str(payload["scope"]))

    store.touch(cid)

    return RefreshTokenRotationResult(
        connection_id=cid,
        portal_url=portal_url,
        attempted=True,
        rotated=True,
        reason="Refresh token rotated successfully.",
        refresh_token_age_seconds=age_seconds,
        rotated_at_epoch=now_epoch,
        username=username
    )
