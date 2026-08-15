from __future__ import annotations

import argparse
import json

from age_oauth import get_gis
from age_oauth.oauth import resolve_identity


TEST_PRIVATE_ITEM_ID = "819e78caf432430d913eaa68d2cb6034"


def _pretty(obj) -> str:
    return json.dumps(
        obj,
        indent=2,
        sort_keys=True,
        default=str,
    )


def test_identity(connection: str):
    """
    Confirm what principal age-oauth believes is authenticated.
    """

    gis = get_gis(
        connection=connection,
        prompt_if_missing=False,
    )

    identity = resolve_identity(
        gis,
        connection=connection,
    )

    print("[IDENTITY]")

    if identity.auth_type == "app":
        print("  type        : application")
        print(f"  application : {identity.app_title}")
        print(f"  app_id      : {identity.app_id}")
        print(f"  item_id     : {identity.app_item_id}")
        print(f"  owner       : {identity.app_owner}")
        print(f"  username    : {identity.username}")

        assert identity.app_id
        assert identity.username is None

        print()
        print("[PASS] Application identity confirmed.")

    else:
        print("  type        : user")
        print(f"  username    : {identity.username}")
        print(f"  source      : {identity.source}")

        assert identity.username

        print()
        print("[PASS] User identity confirmed.")

    print()

    return gis, identity


def test_private_item_access(
    connection: str,
    item_id: str,
):
    """
    Confirm that the authenticated principal can retrieve a protected item
    through the same get_gis() path used by production callers.
    """

    gis = get_gis(
        connection=connection,
        prompt_if_missing=False,
    )

    print(f"[TEST] Fetch protected item: {item_id}")

    item = gis.content.get(item_id)

    if item is None:
        raise AssertionError(
            f"Authenticated principal could not access item {item_id}"
        )

    print("[RESULTS]")
    print(f"  id     : {item.id}")
    print(f"  title  : {item.title}")
    print(f"  type   : {item.type}")
    print(f"  owner  : {item.owner}")
    print(f"  access : {item.access}")

    print()
    print("[PASS] Protected item is accessible through authenticated GIS.")
    print()

    return gis, item


def test_item_data(item):
    """
    For item types that have JSON data, confirm that the authenticated
    principal can also retrieve the item's data payload.
    """

    print("[TEST] Fetch item data")

    try:
        data = item.get_data()
    except Exception as ex:
        raise AssertionError(
            f"Item metadata was visible, but item data retrieval failed: {ex}"
        ) from ex

    if data is None:
        print(
            "[INFO] Item returned no separate data payload. "
            "This may be normal for service items."
        )
        print()
        return None

    print("[RESULTS] Item data retrieved successfully.")

    if isinstance(data, dict):
        print(f"  top-level keys : {', '.join(sorted(data.keys()))}")

    print()
    print("[PASS] Item data is accessible.")
    print()

    return data


def test_service_access(gis, item):
    """
    If the Portal item points to a service URL, query the service endpoint
    through the authenticated GIS connection.

    This is important because Portal item visibility and service access
    are related but not identical tests.
    """

    service_url = getattr(item, "url", None)

    if not service_url:
        print(
            "[INFO] Item has no service URL; "
            "skipping service endpoint test."
        )
        print()
        return None

    print(f"[TEST] Service endpoint: {service_url}")

    # Use the GIS connection so we inherit the same token, referer,
    # SSL behavior, and authentication context.
    response = gis._con.get(
        service_url,
        params={"f": "json"},
    )

    if not response:
        raise AssertionError(
            "Service endpoint returned no response."
        )

    if isinstance(response, dict) and "error" in response:
        raise AssertionError(
            f"Service endpoint returned error: {response['error']}"
        )

    print("[RESULTS] Service endpoint accessible.")

    if isinstance(response, dict):
        print(f"  name         : {response.get('name')}")
        print(f"  type         : {response.get('type')}")
        print(f"  capabilities : {response.get('capabilities')}")

        layers = response.get("layers") or []

        if layers:
            print(f"  layer count  : {len(layers)}")

    print()
    print("[PASS] Service endpoint is accessible using the app identity.")
    print()

    return response


def test_first_layer_query(gis, item):
    """
    If the item is a Feature Service and exposes at least one layer,
    perform a minimal query against layer 0.

    This proves the application can actually read feature content,
    which is much closer to Egress's real workload.
    """

    service_url = getattr(item, "url", None)

    if not service_url:
        print("[INFO] No service URL; skipping layer query.")
        print()
        return

    service_info = gis._con.get(
        service_url,
        params={"f": "json"},
    )

    layers = (
        service_info.get("layers") or []
        if isinstance(service_info, dict)
        else []
    )

    if not layers:
        print("[INFO] Service exposes no layers; skipping layer query.")
        print()
        return

    layer_id = layers[0].get("id")

    if layer_id is None:
        print("[INFO] First layer has no id; skipping layer query.")
        print()
        return

    layer_url = f"{service_url}/{layer_id}/query"

    print(f"[TEST] Query first layer: {layer_url}")

    result = gis._con.get(
        layer_url,
        params={
            "f": "json",
            "where": "1=1",
            "outFields": "*",
            "resultRecordCount": 1,
            "returnGeometry": "false",
        },
    )

    if isinstance(result, dict) and "error" in result:
        raise AssertionError(
            f"Layer query returned error: {result['error']}"
        )

    features = (
        result.get("features") or []
        if isinstance(result, dict)
        else []
    )

    print(f"[RESULTS] Features returned: {len(features)}")

    if features:
        attrs = features[0].get("attributes") or {}
        print(
            "  sample fields : "
            + ", ".join(list(attrs.keys())[:10])
        )

    print()
    print("[PASS] Feature layer query succeeded.")
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Live age-oauth / ArcGIS Enterprise integration test"
    )

    parser.add_argument(
        "--connection",
        required=True,
        help="Named age-oauth connection label or ID",
    )

    parser.add_argument(
        "--item-id",
        default=TEST_PRIVATE_ITEM_ID,
        help="Protected Portal item ID to test",
    )

    parser.add_argument(
        "test",
        nargs="?",
        choices=(
            "identity",
            "item",
            "service",
            "query",
            "all",
        ),
        default="all",
        help="Which integration test to run",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.test == "identity":
        test_identity(args.connection)
        return

    if args.test == "item":
        gis, item = test_private_item_access(
            args.connection,
            args.item_id,
        )

        test_item_data(item)
        return

    if args.test == "service":
        gis, item = test_private_item_access(
            args.connection,
            args.item_id,
        )

        test_service_access(
            gis,
            item,
        )
        return

    if args.test == "query":
        gis, item = test_private_item_access(
            args.connection,
            args.item_id,
        )

        test_first_layer_query(
            gis,
            item,
        )
        return

    # all
    test_identity(
        args.connection,
    )

    gis, item = test_private_item_access(
        args.connection,
        args.item_id,
    )

    test_item_data(
        item,
    )

    test_service_access(
        gis,
        item,
    )

    test_first_layer_query(
        gis,
        item,
    )


if __name__ == "__main__":
    main()