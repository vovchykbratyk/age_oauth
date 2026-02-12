# age_oauth/cli.py
from __future__ import annotations

import argparse
import logging
import sys
import traceback

from typing import Optional

from .connections import ConnectionStore
from .oauth import get_gis


def _prompt(label: str, *, default: Optional[str] = None, secret: bool = False) -> str:
    import getpass

    suffix = f" (default: {default})" if default else ""
    while True:
        if secret:
            v = getpass.getpass(f"{label}{suffix}: ").strip()
        else:
            v = input(f"{label}{suffix}: ").strip()
        if v:
            return v
        if default is not None:
            return default
        print("Value is required.")


def _print_connection(store: ConnectionStore, cid: str) -> None:
    meta = store.load_meta(cid, allow_missing=True)
    env_path = store.env_path(cid)
    meta_path = store.meta_path(cid)

    print(f"ID:         {cid}")
    if meta:
        print(f"Label:      {meta.label}")
        print(f"Portal URL: {meta.portal_url}")
        print(f"Verify SSL: {meta.verify_ssl}")
        if meta.ca_bundle:
            print(f"CA Bundle:  {meta.ca_bundle}")
        print(f"Created:    {meta.created_at}")
        print(f"Last used:  {meta.last_used_at or ''}")
        if meta.tags:
            print(f"Tags:       {', '.join(meta.tags)}")
    print(f"Env file:   {env_path}")
    print(f"Meta file:  {meta_path}")


def main(argv: Optional[list[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]

    p = argparse.ArgumentParser(prog="age-oauth")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable info logging")

    sub = p.add_subparsers(dest="cmd", required=True)

    # ---- connections group ----
    c = sub.add_parser("connections", help="Manage saved ArcGIS Enterprise connections")
    csub = c.add_subparsers(dest="connections_cmd", required=True)

    csub.add_parser("list", help="List connections")

    add = csub.add_parser("add", help="Add a new connection (prompts if args omitted)")
    add.add_argument("--label", help="Display label (e.g. 'Prod')")
    add.add_argument("--portal", help="Portal URL (e.g. https://host/portal)")
    add.add_argument("--verify-ssl", default="true", help="true/false/path (default: true)")
    add.add_argument("--client-id", default=None, help="OAuth client id")
    add.add_argument("--client-secret", default=None, help="OAuth client secret")
    add.add_argument("--no-active", action="store_true", help="Do not set as active connection")
    add.add_argument("--no-default", action="store_true", help="Do not set as default connection")

    use = csub.add_parser("use", help="Set active connection")
    use.add_argument("selector", help="Connection id or label")

    show = csub.add_parser("show", help="Show connection details")
    show.add_argument("selector", nargs="?", help="Connection id or label (default: active/default)")

    info = csub.add_parser("info", help="Show store location and current selection")

    # ---- auth commands ----
    login = sub.add_parser("login", help="Authenticate (interactive) and cache tokens")
    login.add_argument("--connection", default=None, help="Connection id or label")
    login.add_argument("--connection-id", default=None, help="Explicit connection ID")

    whoami = sub.add_parser("whoami", help="Print authenticated username")
    whoami.add_argument("--connection", default=None, help="Connection id or label")
    whoami.add_argument("--connection-id", default=None, help="Explicit connection ID")

    args = p.parse_args(argv)

    level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")
    log = logging.getLogger("age_oauth")

    store = ConnectionStore()

    try:
        if args.cmd == "connections":
            if args.connections_cmd == "info":
                print(f"Store base: {store.base_dir()}")
                log.info("Store base dir: %s", store.base_dir())
                active = store.get_active()
                default = store.get_default()
                print(f"Active:     {active or ''}")
                print(f"Default:    {default or ''}")
                return 0

            if args.connections_cmd == "list":
                conns = store.list()
                active = store.get_active()
                default = store.get_default()

                if not conns:
                    print("No connections found. Add one with: age-oauth connections add")
                    return 0

                # simple aligned output
                for m in conns:
                    marks = []
                    if active and m.id == active:
                        marks.append("active")
                    if default and m.id == default:
                        marks.append("default")
                    mark = f" ({', '.join(marks)})" if marks else ""
                    print(f"{m.id}{mark}  -  {m.label}  -  {m.portal_url}")
                return 0

            if args.connections_cmd == "add":
                label = args.label or _prompt("Connection label", default="Prod")
                portal = args.portal or _prompt("Portal URL (e.g. https://host/portal)")
                verify_ssl = args.verify_ssl or _prompt("Verify SSL? [true/false/path]", default="true")
                client_id = args.client_id or _prompt("OAuth Client ID")
                client_secret = args.client_secret or _prompt("OAuth Client Secret", secret=True)

                cid = store.create(
                    label=label,
                    portal_url=portal,
                    client_id=client_id,
                    client_secret=client_secret,
                    verify_ssl=verify_ssl,
                    make_active=not args.no_active,
                    make_default=not args.no_default,
                )

                print(f"[OK] Created connection: {cid}")
                _print_connection(store, cid)
                return 0

            if args.connections_cmd == "use":
                cid = store.resolve(connection=args.selector)
                log.info("Resolving connection selector: %r", args.selector)
                store.set_active(cid)
                log.info("Resolved connection id:%s", cid)
                print(f"[OK] Active connection set: {cid}")
                return 0

            if args.connections_cmd == "show":
                selector = args.selector
                log.info("Resolving connection selector: %r", args.selector)
                cid = store.resolve(connection=selector) if selector else store.resolve()
                log.info("Resolved connection id:%s", cid)
                _print_connection(store, cid)
                return 0

            raise RuntimeError("Unhandled connections subcommand")

        # ---- login / whoami ----
        if args.cmd in ("login", "whoami"):
            selector = getattr(args, "connection", None)
            log.info("Resolving connection selector: %r", args.selector)
            # get_gis handles resolving + prompting via ConnectionStore mode.
            gis = get_gis(connection=selector) if selector else get_gis()

            if args.cmd == "whoami":
                me = gis.users.me
                print(getattr(me, "username", None) or "unknown")
                return 0

            # login
            print("[OK] GIS object created.")
            return 0

        raise RuntimeError("Unhandled command")

    except KeyboardInterrupt:
        print("\n[ABORTED] Cancelled by user.")
        return 130
    except Exception as ex:
        print(f"[ERROR] {ex}")
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
