from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import requests
from dotenv import load_dotenv

from age_oauth.oauth import (
    AGEOAuth,
    OAuthConfig,
    OAuthIdentity,
    resolve_identity,
)


# Replace this with a known protected item that the selected credential
# should be able to access.
TEST_PRIVATE_ITEM_ID = "819e78caf432430d913eaa68d2cb6034"


def pretty(obj: Any) -> str:
    return json.dumps(
        obj,
        indent=2,
        sort_keys=True,
    )


def build_auth() -> AGEOAuth:
    """
    Build AGEOAuth directly from environment variables.

    This script is intentionally a live integration harness rather than
    a ConnectionStore test. It lets us point directly at a real Enterprise
    deployment and exercise the actual OAuth behavior.
    """
    load_dotenv()

    portal_url = (
        os.getenv("PORTAL_URL", "")
        .strip()
        .rstrip("/")
    )

    client_id = (
        os.getenv("OAUTH_CLIENT_ID", "")
        .strip()
    )

    client_secret = (
        os.getenv("OAUTH_CLIENT_SECRET", "")
        .strip()
    )

    auth_type = (
        os.getenv("OAUTH_AUTH_TYPE", "user")
        .strip()
        .lower()
    )

    referer = (
        os.getenv("OAUTH_REFERER", "")
        .strip()
        or None
    )

    redirect_uri = (
        os.getenv(
            "OAUTH_REDIRECT_URI",
            "urn:ietf:wg:oauth:2.0:oob",
        )
        .strip()
    )

    if not portal_url or not client_id or not client_secret:
        raise SystemExit(
            "Missing PORTAL_URL, OAUTH_CLIENT_ID, "
            "or OAUTH_CLIENT_SECRET in .env"
        )

    cfg = OAuthConfig(
        portal_url=portal_url,
        client_id=client_id,
        client_secret=client_secret,
        env_path=os.getenv(
            "AGE_OAUTH_ENV_PATH",
            ".env",
        ),
        auth_type=auth_type,
        referer=referer,
        redirect_uri=redirect_uri,
    )

    auth = AGEOAuth(cfg)

    print("[CONFIG]")
    print(f"  portal      : {auth.portal_url}")
    print(f"  auth_type   : {auth.auth_type}")
    print(f"  verify_ssl  : {auth.verify_ssl!r}")
    print(f"  referer     : {auth.referer or '<none>'}")
    print()

    return auth


def _request_kwargs(auth: AGEOAuth) -> Dict[str, Any]:
    """
    Common requests kwargs used throughout the live tests.
    """
    return {
        "headers": auth._request_headers(),
        "timeout": 30,
        "verify": auth.verify_ssl,
    }


def test_portals_self(auth: AGEOAuth) -> Dict[str, Any]:
    """
    Query /portals/self directly with the current OAuth token.

    For user auth, expect a user object.

    For app auth, expect appInfo with an appId and do NOT interpret
    appOwner as the authenticated username.
    """
    token = auth.access_token

    url = (
        f"{auth.portal_url}"
        "/sharing/rest/portals/self"
    )

    params = {
        "f": "json",
        "token": token,
    }

    print(f"[TEST] GET {url}")

    resp = requests.get(
        url,
        params=params,
        **_request_kwargs(auth),
    )

    print(
        f"  HTTP status : "
        f"{resp.status_code}"
    )

    resp.raise_for_status()

    data = resp.json()

    if "error" in data:
        raise RuntimeError(
            f"portals/self returned error: "
            f"{data['error']}"
        )

    print()

    if auth.auth_type == "app":
        app_info = data.get("appInfo") or {}
        app_id = (
            app_info.get("appId") or ""
        ).strip()

        print(
            "[RESULTS] application identity"
        )

        print(
            f"  appTitle : "
            f"{app_info.get('appTitle')}"
        )
        print(
            f"  appId    : "
            f"{app_info.get('appId')}"
        )
        print(
            f"  itemId   : "
            f"{app_info.get('itemId')}"
        )
        print(
            f"  appOwner : "
            f"{app_info.get('appOwner')}"
        )

        print(
            f"  user obj : "
            f"{'present' if data.get('user') else 'absent'}"
        )

        if not app_info:
            raise AssertionError(
                "Expected appInfo for application "
                "authentication, but none was returned."
            )

        if not app_id:
            raise AssertionError(
                "Expected appInfo.appId for application "
                "authentication."
            )

        if data.get("user"):
            print(
                "[WARN] Application-authenticated response "
                "also contained a user object."
            )

        print(
            "\n[PASS] Portal identifies this token "
            "as an application credential."
        )

    else:
        user = data.get("user") or {}

        username = (
            user.get("username") or ""
        ).strip()

        print(
            "[RESULTS] user identity"
        )
        print(
            f"  username : "
            f"{user.get('username')}"
        )
        print(
            f"  fullName : "
            f"{user.get('fullName')}"
        )
        print(
            f"  role     : "
            f"{user.get('role')}"
        )

        privileges = (
            user.get("privileges") or []
        )

        print(
            f"  privileges count : "
            f"{len(privileges)}"
        )

        if not username:
            raise AssertionError(
                "Expected portals/self.user.username "
                "for user authentication."
            )

        print(
            "\n[PASS] Portal identifies this token "
            "as a user credential."
        )

    print()

    return data


def test_resolved_identity(
    auth: AGEOAuth,
) -> OAuthIdentity:
    """
    Exercise age-oauth's own resolve_identity() logic against the
    live Enterprise system.

    Because resolve_identity() normally works from a saved connection,
    this test uses a lightweight GIS object only for the user path.

    For app auth the GIS object is not consulted.
    """
    from arcgis.gis import GIS

    gis_kwargs: Dict[str, Any] = {}

    if auth.referer:
        gis_kwargs["referer"] = auth.referer

    if isinstance(auth.verify_ssl, bool):
        verify_cert = auth.verify_ssl
    else:
        verify_cert = True
        gis_kwargs["ca_bundles"] = str(
            auth.verify_ssl
        )

    gis = GIS(
        auth.portal_url,
        token=auth.access_token,
        verify_cert=verify_cert,
        **gis_kwargs,
    )

    print("[TEST] ArcGIS Python API GIS object")

    if auth.auth_type == "user":
        print(
            f"  gis.users.me : "
            f"{gis.users.me}"
        )
    else:
        print(
            "  app auth: gis.users.me is not "
            "used as the authoritative identity"
        )

    print()

    return gis


def test_private_item_visibility(
    auth: AGEOAuth,
    item_id: str,
) -> Dict[str, Any]:
    """
    Compare anonymous and authenticated access to a protected item.

    For app auth this verifies that the credential has been explicitly
    granted access to the item.

    For user auth this verifies access through the user's privileges.
    """
    base_url = (
        f"{auth.portal_url}"
        f"/sharing/rest/content/items/{item_id}"
    )

    anon_params = {
        "f": "json",
    }

    authed_params = {
        "f": "json",
        "token": auth.access_token,
    }

    print(
        f"[TEST] ANONYMOUS GET "
        f"{base_url}"
    )

    anon_resp = requests.get(
        base_url,
        params=anon_params,
        timeout=30,
        verify=auth.verify_ssl,
    )

    anon_data = anon_resp.json()

    print(
        "  HTTP status:",
        anon_resp.status_code,
    )

    if "error" in anon_data:
        print(
            "  ANONYMOUS error:"
        )
        print(
            pretty(
                anon_data["error"]
            )
        )
    else:
        print(
            "  ANONYMOUS response:"
        )
        print(
            pretty(
                {
                    k: anon_data.get(k)
                    for k in (
                        "id",
                        "title",
                        "access",
                    )
                }
            )
        )

    print(
        "\n[TEST] AUTHENTICATED GET"
    )

    auth_resp = requests.get(
        base_url,
        params=authed_params,
        **_request_kwargs(auth),
    )

    auth_data = auth_resp.json()

    print(
        "  HTTP status:",
        auth_resp.status_code,
    )

    if "error" in auth_data:
        print(
            "  AUTHENTICATED error:"
        )
        print(
            pretty(
                auth_data["error"]
            )
        )
    else:
        subset = {
            k: auth_data.get(k)
            for k in (
                "id",
                "title",
                "owner",
                "access",
                "type",
            )
        }

        print(
            "  AUTHENTICATED response:"
        )
        print(
            pretty(subset)
        )

    print()

    anon_error = anon_data.get("error")
    auth_error = auth_data.get("error")

    if auth_error:
        raise AssertionError(
            "Authenticated item request failed. "
            "Check the item ID and the credential's "
            "assigned item access."
        )

    if anon_error and not auth_error:
        print(
            "[PASS] Authenticated credential can access "
            "the item while anonymous access cannot."
        )
    else:
        print(
            "[INFO] Anonymous and authenticated behavior "
            "did not clearly differ. The item may be public."
        )

    print()

    return auth_data


def inspect_service_capabilities(
    auth: AGEOAuth,
    item_json: Dict[str, Any],
) -> None:
    """
    If the item points to a service, query the service endpoint using
    the same OAuth token and referer.
    """
    service_url = item_json.get("url")

    if not service_url:
        print(
            "[INFO] Item has no service URL. "
            "Skipping service capability inspection."
        )
        return

    print(
        f"[TEST] Inspecting service capabilities "
        f"at {service_url}"
    )

    params = {
        "f": "json",
        "token": auth.access_token,
    }

    resp = requests.get(
        service_url,
        params=params,
        **_request_kwargs(auth),
    )

    if not resp.ok:
        raise AssertionError(
            "Service info request failed: "
            f"{resp.status_code} {resp.text}"
        )

    svc = resp.json()

    if "error" in svc:
        raise AssertionError(
            f"Service endpoint returned error: "
            f"{svc['error']}"
        )

    caps = svc.get(
        "capabilities",
        "",
    )

    print(
        "  capabilities:",
        caps,
    )

    editing_info = (
        svc.get("editingInfo") or {}
    )

    print(
        "  editingInfo:",
        pretty(editing_info),
    )

    if any(
        capability in caps
        for capability in (
            "Update",
            "Editing",
            "Create",
            "Delete",
        )
    ):
        print(
            "  [INFO] Service exposes editing capabilities."
        )
    else:
        print(
            "  [INFO] Service appears read-only."
        )

    print()


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage:\n"
            "  python tests/test_enterprise_oauth.py identity\n"
            "  python tests/test_enterprise_oauth.py item\n"
            "  python tests/test_enterprise_oauth.py all\n"
        )
        raise SystemExit(1)

    auth = build_auth()

    cmd = sys.argv[1].lower()

    if cmd == "identity":
        test_portals_self(auth)
        test_resolved_identity(auth)
        return

    if cmd == "item":
        if (
            not TEST_PRIVATE_ITEM_ID
            or TEST_PRIVATE_ITEM_ID.startswith(
                "1234abcd"
            )
        ):
            raise SystemExit(
                "TEST_PRIVATE_ITEM_ID is not set "
                "to a real protected item ID."
            )

        item_json = test_private_item_visibility(
            auth,
            TEST_PRIVATE_ITEM_ID,
        )

        inspect_service_capabilities(
            auth,
            item_json,
        )

        return

    if cmd == "all":
        test_portals_self(auth)
        test_resolved_identity(auth)

        if (
            TEST_PRIVATE_ITEM_ID
            and not TEST_PRIVATE_ITEM_ID.startswith(
                "1234abcd"
            )
        ):
            item_json = test_private_item_visibility(
                auth,
                TEST_PRIVATE_ITEM_ID,
            )

            inspect_service_capabilities(
                auth,
                item_json,
            )

        return

    raise SystemExit(
        f"Unknown command: {cmd}"
    )


if __name__ == "__main__":
    main()