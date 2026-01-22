from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import requests
from dotenv import load_dotenv

from src.age_oauth.oauth import AGEOAuth, OAuthConfig

# replace this with some known non-public item you can access
TEST_PRIVATE_ITEM_ID = "1234abcd5678efgh1234abcd5678efgh"


def pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def build_auth() -> AGEOAuth:
    load_dotenv()

    portal_url = os.getenv("PORTAL_URL", "").rstrip("/")
    client_id = os.getenv("OAUTH_CLIENT_ID", "")
    client_secret = os.getenv("OAUTH_CLIENT_SECRET", "")

    if not portal_url or not client_id or not client_secret:
        raise SystemExit(
            "Missing PORTAL_URL, OAUTH_CLIENT_ID, or OAUTH_CLIENT_SECRET in .env"
        )

    cfg = OAuthConfig(
        portal_url=portal_url,
        client_id=client_id,
        client_secret=client_secret,
    )
    auth = AGEOAuth(cfg)
    print(f"[DEBUG] auth.verify_ssl = {auth.verify_ssl!r}")
    return auth


def test_whoami(auth: AGEOAuth) -> Dict[str, Any]:
    """
    Call /portals/self to confirm identity + capture privileges.
    """
    token = auth.access_token
    url = f"{auth.portal_url}/sharing/rest/portals/self"
    params = {"f": "json", "token": token}

    print(f"[TEST] GET {url}")
    resp = requests.get(url, params=params, timeout=30, verify=auth.verify_ssl)
    resp.raise_for_status()
    data = resp.json()

    user = data.get("user", {})
    print("\n[RESULTS] portals/self user info:")
    print(f"  username : {user.get('username')}")
    print(f"  fullName : {user.get('fullName')}")
    print(f"  role     : {user.get('role')}")

    privs = user.get("privileges") or []
    print(f"  privileges count : {len(privs)}")
    # uncomment this if you want to look at all privileges
    # print("  privileges:", privs)

    print()
    return data


def test_private_item_visibility(auth: AGEOAuth, item_id: str) -> Dict[str, Any]:
    """
    Test anonymous vs authenticated access. This proves the token gives you
    access to protected items (as long as your user acct can see them).
    """
    base_url = f"{auth.portal_url}/sharing/rest/content/items/{item_id}"

    anon_params = {"f": "json"}
    authed_params = {"f": "json", "token": auth.access_token}

    print(f"[TEST] ANONYMOUS GET {base_url}")
    anon_resp = requests.get(base_url, params=anon_params, timeout=30, verify=auth.verify_ssl)
    anon_data = anon_resp.json()
    print("  HTTP status:", anon_resp.status_code)

    if "error" in anon_data:
        print("  ANONYMOUS error:")
        print(pretty(anon_data["error"]))
    else:
        print("  ANONYMOUS response (partial):")
        print(pretty({k: anon_data.get(k) for k in ("id", "title", "access")}))

    print("\n[TEST] AUTHENTICATED GET (with OAuth token)")
    auth_resp = requests.get(base_url, params=authed_params, timeout=30, verify=auth.verify_ssl)
    auth_data = auth_resp.json()
    print("  HTTP status:", auth_resp.status_code)

    if "error" in auth_data:
        print("  AUTHENTICATED error:")
        print(pretty(auth_data["error"]))
    else:
        subset = {k: auth_data.get(k) for k in ("id", "title", "owner", "access", "type")}
        print("  AUTHENTICATED response (key fields):")
        print(pretty(subset))

    print()

    anon_error = anon_data.get("error")
    auth_error = auth_data.get("error")

    if auth_error:
        print("[RESULTS] Authenticated request failed... check item_id and your access.")
    elif anon_error and not auth_error:
        print("[RESULTS] OAuth client CAN see this item while anonymous access CANNOT.")
    else:
        print(
            "[RESULTS] Item might be public, or anonymous and authed behaved the same.\n"
            "Use a truly private/org-only item to verify user-scoped behavior."
        )

    return auth_data


def inspect_service_capabilities(auth: AGEOAuth, item_json: Dict[str, Any]) -> None:
    """
    If the item points to a feature/map service, pull capabilities to figure out
    what operations are allowed (Query, Create, Update, Delete, etc.).
    """
    service_url = item_json.get("url")
    if not service_url:
        print("[INFO] Item has no 'url' field... might be a web map, file, or something non-service.")
        return

    print(f"[TEST] Inspecting service capabilities at {service_url}")
    params = {"f": "json", "token": auth.access_token}
    resp = requests.get(service_url, params=params, timeout=30, verify=auth.verify_ssl)
    if not resp.ok:
        print(f"\tService info request failed: {resp.status_code} {resp.text}")
        return

    svc = resp.json()
    caps = svc.get("capabilities", "")
    print("  capabilities:", caps)

    editing_info = svc.get("editingInfo") or {}
    print("  editingInfo:", pretty(editing_info))

    # Quick interpretation
    if "Update" in caps or "Editing" in caps or "Create" in caps or "Delete" in caps:
        print("  [READ-WRITE] This service is configured to allow edits.")
    else:
        print("  [READ-ONLY] This service appears read-only from the service side.")

    print()


def main():
    if len(sys.argv) < 2:
        print(
            "Usage:\n"
            "  python test_enterprise_oauth.py whoami\n"
            "  python test_enterprise_oauth.py item\n"
        )
        raise SystemExit(1)

    auth = build_auth()
    cmd = sys.argv[1].lower()

    if cmd == "whoami":
        test_whoami(auth)

    elif cmd == "item":
        if not TEST_PRIVATE_ITEM_ID or TEST_PRIVATE_ITEM_ID.startswith("your_real"):
            raise SystemExit(
                "TEST_PRIVATE_ITEM_ID is not set to a real non-public item id."
            )

        portals_self = test_whoami(auth)
        item_json = test_private_item_visibility(auth, TEST_PRIVATE_ITEM_ID)
        inspect_service_capabilities(auth, item_json)

    else:
        print(f"Unknown command: {cmd}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
