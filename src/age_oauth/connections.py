# age_oauth/connections.py
from __future__ import annotations

import json
import os
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from platformdirs import user_config_dir

from .envfile import parse_env_file, set_env_key

# core keys for usable Enterprise connection profile
_REQUIRED_KEYS = ("PORTAL_URL", "OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(data, indent=2, sort_keys=False) + "\n")


def _read_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        # If corrupted, keep going but don't silently destroy data.
        raise RuntimeError(f"Unable to parse JSON file: {path}")


def _slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_") or "connection"


def _normalize_portal_url(url: str) -> str:
    url = (url or "").strip()
    url = url.rstrip("/")
    return url


def _make_connection_id(label: str, portal_url: str) -> str:
    """
    Stable-ish, readable ID. Collision risk is extremely low for normal usage.
    """
    slug = _slugify(label)
    h = hashlib.sha1(_normalize_portal_url(portal_url).encode("utf-8")).hexdigest()[:8]
    return f"{slug}_{h}"


def _coerce_verify_ssl_input(raw: str) -> Tuple[bool, Optional[str], str]:
    """
    Normalize verify SSL input into:
      - verify_ssl bool
      - ca_bundle path (optional)
      - persisted string value for OAUTH_VERIFY_SSL
    Rules:
      - "true"/"false" -> bool
      - otherwise treat as filesystem path (must exist)
    """
    s = (raw or "").strip()
    if not s:
        s = "true"
    v = s.lower()
    if v in ("false", "0", "no", "off"):
        return False, None, "false"
    if v in ("true", "1", "yes", "on"):
        return True, None, "true"

    # path
    p = Path(s).expanduser()
    if not p.exists():
        raise ValueError(f"Verify SSL path does not exist: {s}")
    return True, str(p), str(p)


@dataclass(frozen=True)
class ConnectionMeta:
    id: str
    label: str
    portal_url: str
    created_at: str
    last_used_at: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    verify_ssl: bool = True
    ca_bundle: Optional[str] = None


class ConnectionStore:
    """
    Stores multiple ArcGIS Enterprise connection profiles.

    Layout:
      <base>/
        connections.json
        active_connection
        connections/
          <id>/
            .env
            meta.json

    No external deps beyond platformdirs + stdlib.
    """

    SCHEMA_VERSION = 1

    def __init__(self, base_dir: Optional[Path] = None):
        self._base_dir = base_dir

    # -------------------------
    # Paths
    # -------------------------

    def base_dir(self) -> Path:
        if self._base_dir is not None:
            return self._base_dir
        # Vendor/appname are optional; keep it simple.
        return Path(user_config_dir("age_oauth"))

    def connections_dir(self) -> Path:
        return self.base_dir() / "connections"

    def index_path(self) -> Path:
        return self.base_dir() / "connections.json"

    def active_path(self) -> Path:
        return self.base_dir() / "active_connection"

    def conn_dir(self, connection_id: str) -> Path:
        return self.connections_dir() / connection_id

    def env_path(self, connection_id: str) -> Path:
        return self.conn_dir(connection_id) / ".env"

    def meta_path(self, connection_id: str) -> Path:
        return self.conn_dir(connection_id) / "meta.json"

    # -------------------------
    # Index helpers
    # -------------------------

    def _default_index(self) -> Dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "default_connection_id": None,
            "connections": [],
        }

    def _load_index(self) -> Dict[str, Any]:
        idx = _read_json(self.index_path(), self._default_index())
        sv = idx.get("schema_version")
        if sv is None:
            # allow legacy-ish file without schema_version
            idx["schema_version"] = self.SCHEMA_VERSION
        elif sv != self.SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported connections.json schema_version={sv} (expected {self.SCHEMA_VERSION})"
            )
        if "connections" not in idx or not isinstance(idx["connections"], list):
            raise RuntimeError(f"Invalid connections index structure: {self.index_path()}")
        return idx

    def _save_index(self, idx: Dict[str, Any]) -> None:
        _atomic_write_json(self.index_path(), idx)

    def _find_in_index(self, idx: Dict[str, Any], connection_id: str) -> Optional[Dict[str, Any]]:
        for c in idx.get("connections", []):
            if c.get("id") == connection_id:
                return c
        return None

    # -------------------------
    # Public operations
    # -------------------------

    def list(self) -> List[ConnectionMeta]:
        """
        Return all connections from index, enriched (best-effort) with meta.json if present.
        """
        idx = self._load_index()
        out: List[ConnectionMeta] = []
        for c in idx.get("connections", []):
            cid = c.get("id") or ""
            if not cid:
                continue

            # Prefer meta.json if present (source of truth), but fall back to index fields
            meta = self.load_meta(cid, allow_missing=True)
            if meta is None:
                out.append(
                    ConnectionMeta(
                        id=cid,
                        label=c.get("label") or cid,
                        portal_url=c.get("portal_url") or "",
                        created_at=c.get("created_at") or "",
                        last_used_at=c.get("last_used_at"),
                        tags=list(c.get("tags") or []),
                        verify_ssl=bool(c.get("verify_ssl", True)),
                        ca_bundle=c.get("ca_bundle"),
                    )
                )
            else:
                out.append(meta)
        return out

    def get_active(self) -> Optional[str]:
        p = self.active_path()
        if not p.exists():
            return None
        cid = p.read_text(encoding="utf-8").strip()
        return cid or None

    def set_active(self, connection_id: str) -> None:
        self._assert_exists(connection_id)
        _atomic_write_text(self.active_path(), connection_id.strip() + "\n")

    def get_default(self) -> Optional[str]:
        idx = self._load_index()
        cid = idx.get("default_connection_id")
        return str(cid) if cid else None

    def set_default(self, connection_id: str) -> None:
        self._assert_exists(connection_id)
        idx = self._load_index()
        idx["default_connection_id"] = connection_id
        self._save_index(idx)

    def resolve(self, *, connection: Optional[str] = None, connection_id: Optional[str] = None) -> str:
        """
        Resolve a connection selector to a connection_id.

        Precedence:
          1) connection_id (exact)
          2) connection (match id exact, else label case-insensitive exact, else unique prefix match)
          3) active_connection
          4) default_connection_id
          5) if exactly one connection exists, use it
          else -> error
        """
        idx = self._load_index()
        conns = idx.get("connections", [])

        if connection_id:
            cid = connection_id.strip()
            if not self._find_in_index(idx, cid) and not self.conn_dir(cid).exists():
                raise RuntimeError(f"Unknown connection_id: {cid}")
            return cid

        if connection:
            sel = connection.strip()

            # exact id
            for c in conns:
                if c.get("id") == sel:
                    return sel

            # exact label (case-insensitive)
            matches = [c for c in conns if (c.get("label") or "").lower() == sel.lower()]
            if len(matches) == 1:
                return matches[0]["id"]
            if len(matches) > 1:
                raise RuntimeError(f"Ambiguous connection label: {sel!r} (multiple matches)")

            # unique prefix of id
            prefix = sel.lower()
            pm = [c for c in conns if (c.get("id") or "").lower().startswith(prefix)]
            if len(pm) == 1:
                return pm[0]["id"]
            if len(pm) > 1:
                raise RuntimeError(f"Ambiguous connection selector: {sel!r} (multiple id prefix matches)")

            raise RuntimeError(f"No connection found matching selector: {sel!r}")

        active = self.get_active()
        if active:
            return active

        default = idx.get("default_connection_id")
        if default:
            return str(default)

        if len(conns) == 1 and conns[0].get("id"):
            return conns[0]["id"]

        raise RuntimeError(
            "No connection selected. Create one with 'age-oauth connections add', "
            "or set an active connection with 'age-oauth connections use <id>'."
        )

    def create(
        self,
        *,
        label: str,
        portal_url: str,
        client_id: str,
        client_secret: str,
        verify_ssl: str = "true",
        make_active: bool = True,
        make_default: bool = True,
    ) -> str:
        """
        Create a new connection profile:
          - creates folder + meta.json + .env with core settings
          - adds entry in connections.json
          - optionally sets as active/default
        """
        label = (label or "").strip()
        if not label:
            raise ValueError("label is required")
        portal_url = _normalize_portal_url(portal_url)
        if not portal_url:
            raise ValueError("portal_url is required")

        cid = _make_connection_id(label, portal_url)
        cdir = self.conn_dir(cid)
        cdir.mkdir(parents=True, exist_ok=True)

        verify_bool, ca_bundle, persisted_verify = _coerce_verify_ssl_input(verify_ssl)

        # Seed .env (core keys + verify)
        env_path = self.env_path(cid)
        if not env_path.exists():
            env_template = (
                "# age_oauth connection profile (.env)\n"
                "# Token fields will be written below automatically after first login.\n"
                "PORTAL_URL=''\n"
                "OAUTH_CLIENT_ID=''\n"
                "OAUTH_CLIENT_SECRET=''\n"
                "OAUTH_VERIFY_SSL=''\n"
                "\n"
            )
            env_path.write_text(env_template, encoding="utf-8")

        set_env_key(str(env_path), "PORTAL_URL", portal_url)
        set_env_key(str(env_path), "OAUTH_CLIENT_ID", client_id)
        set_env_key(str(env_path), "OAUTH_CLIENT_SECRET", client_secret)
        set_env_key(str(env_path), "OAUTH_VERIFY_SSL", persisted_verify)

        # Write meta.json
        meta = ConnectionMeta(
            id=cid,
            label=label,
            portal_url=portal_url,
            created_at=_utc_now_iso(),
            last_used_at=None,
            tags=[],
            verify_ssl=verify_bool,
            ca_bundle=ca_bundle,
        )
        self.save_meta(meta)

        # Update index
        idx = self._load_index()
        existing = self._find_in_index(idx, cid)
        if existing is None:
            idx["connections"].append(
                {
                    "id": meta.id,
                    "label": meta.label,
                    "portal_url": meta.portal_url,
                    "created_at": meta.created_at,
                    "last_used_at": meta.last_used_at,
                    "tags": list(meta.tags),
                    "verify_ssl": meta.verify_ssl,
                    "ca_bundle": meta.ca_bundle,
                }
            )
        else:
            # If it already exists, update label/url but don't overwrite created_at unless missing.
            existing["label"] = meta.label
            existing["portal_url"] = meta.portal_url
            existing.setdefault("created_at", meta.created_at)
            existing["verify_ssl"] = meta.verify_ssl
            existing["ca_bundle"] = meta.ca_bundle

        self._save_index(idx)

        if make_active:
            self.set_active(cid)
        if make_default:
            self.set_default(cid)

        return cid

    def load_meta(self, connection_id: str, *, allow_missing: bool = False) -> Optional[ConnectionMeta]:
        p = self.meta_path(connection_id)
        if not p.exists():
            return None if allow_missing else self._raise_missing(connection_id)
        data = _read_json(p, {})
        return ConnectionMeta(
            id=data["id"],
            label=data.get("label") or data["id"],
            portal_url=data.get("portal_url") or "",
            created_at=data.get("created_at") or "",
            last_used_at=data.get("last_used_at"),
            tags=data.get("tags") or [],
            verify_ssl=bool(data.get("verify_ssl", True)),
            ca_bundle=data.get("ca_bundle"),
        )

    def save_meta(self, meta: ConnectionMeta) -> None:
        p = self.meta_path(meta.id)
        payload = {
            "id": meta.id,
            "label": meta.label,
            "portal_url": meta.portal_url,
            "created_at": meta.created_at,
            "last_used_at": meta.last_used_at,
            "tags": list(meta.tags),
            "verify_ssl": meta.verify_ssl,
            "ca_bundle": meta.ca_bundle,
        }
        _atomic_write_json(p, payload)

    def touch(self, connection_id: str) -> None:
        now = _utc_now_iso()

        meta = self.load_meta(connection_id, allow_missing=True)
        if meta is not None:
            self.save_meta(
                ConnectionMeta(
                    id=meta.id,
                    label=meta.label,
                    portal_url=meta.portal_url,
                    created_at=meta.created_at,
                    last_used_at=now,
                    tags=meta.tags,
                    verify_ssl=meta.verify_ssl,
                    ca_bundle=meta.ca_bundle,
                )
            )

        idx = self._load_index()
        entry = self._find_in_index(idx, connection_id)
        if entry is not None:
            entry["last_used_at"] = now
            self._save_index(idx)

    def ensure_ready(self, connection_id: str, *, prompt: bool = True) -> None:
        """
        Ensure the connection's env file exists and has required core keys.
        If prompt=True, interactively prompts for missing items and writes them.
        """
        env_path = self.env_path(connection_id)
        env_path.parent.mkdir(parents=True, exist_ok=True)

        if not env_path.exists():
            env_template = (
                "# age_oauth connection profile (.env)\n"
                "# Token fields will be written below automatically after first login.\n"
                "PORTAL_URL=''\n"
                "OAUTH_CLIENT_ID=''\n"
                "OAUTH_CLIENT_SECRET=''\n"
                "OAUTH_VERIFY_SSL=''\n"
                "\n"
            )
            env_path.write_text(env_template, encoding="utf-8")

        data = parse_env_file(env_path)
        missing = [k for k in _REQUIRED_KEYS if not data.get(k, "").strip()]

        if not missing:
            return

        if not prompt:
            raise RuntimeError(
                f"Missing required OAuth settings for connection {connection_id}: {', '.join(missing)}"
            )

        print(f"[INFO] Missing required OAuth settings for connection {connection_id}.")
        self._prompt_for_core_settings(connection_id, env_path, existing=data)

    def _prompt_for_core_settings(self, connection_id: str, env_path: Path, existing: Dict[str, str]) -> None:
        """
        Prompt for core settings (same UX as legacy).
        """
        import getpass

        def ask_required(label: str, key: str, secret: bool = False) -> str:
            ex = (existing.get(key) or "").strip()
            if ex:
                return ex
            while True:
                val = getpass.getpass(f"{label}: ").strip() if secret else input(f"{label}: ").strip()
                if val:
                    return val
                print("Value is required.")

        portal_url = ask_required("Portal URL (e.g. https://host/portal)", "PORTAL_URL").rstrip("/")
        client_id = ask_required("OAuth Client ID", "OAUTH_CLIENT_ID")
        client_secret = ask_required("OAuth Client Secret", "OAUTH_CLIENT_SECRET", secret=True)

        ssl_existing = (existing.get("OAUTH_VERIFY_SSL") or "").strip()
        if ssl_existing:
            ssl_val = ssl_existing
        else:
            ssl_val = input("Verify SSL? [true/false/path] (default: true): ").strip() or "true"

        # Validate SSL value (bool or existing path)
        _, _, persisted_verify = _coerce_verify_ssl_input(ssl_val)

        set_env_key(str(env_path), "PORTAL_URL", portal_url)
        set_env_key(str(env_path), "OAUTH_CLIENT_ID", client_id)
        set_env_key(str(env_path), "OAUTH_CLIENT_SECRET", client_secret)
        set_env_key(str(env_path), "OAUTH_VERIFY_SSL", persisted_verify)

        # keep meta in sync (label unchanged)
        meta = self.load_meta(connection_id, allow_missing=True)
        if meta is not None:
            vb, ca, _ = _coerce_verify_ssl_input(persisted_verify)
            self.save_meta(
                ConnectionMeta(
                    id=meta.id,
                    label=meta.label,
                    portal_url=portal_url,
                    created_at=meta.created_at,
                    last_used_at=meta.last_used_at,
                    tags=meta.tags,
                    verify_ssl=vb,
                    ca_bundle=ca,
                )
            )

        print(f"[OK] Updated connection settings: {connection_id}")

    # -------------------------
    # Internal asserts
    # -------------------------

    def _assert_exists(self, connection_id: str) -> None:
        idx = self._load_index()
        if self._find_in_index(idx, connection_id) is None and not self.conn_dir(connection_id).exists():
            self._raise_missing(connection_id)

    def _raise_missing(self, connection_id: str):
        raise RuntimeError(f"Connection does not exist: {connection_id}")
