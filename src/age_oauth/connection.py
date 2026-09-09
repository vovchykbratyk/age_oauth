from __future__ import annotations

from .connections import ConnectionMeta, ConnectionStore


class Connection:
    """
    represents a saved connection profile

    Connection is intended as the primary entry point for scripts or
    applications.  Connections need to be onboarded first via CLI,
    see the README.

    for example

        from age-oauth import Connection

        portal = Connection("some_connection")

        # then to set up your access object,

        p = portal.get_gis()

    

    auth, token refresh, arcgis.gis.GIS construction are handed off
    to age_oauth.oauth.get_gis()
    """

    def __init__(
        self,
        connection: str | None = None,
        *,
        connection_id: str | None = None,
    ):
        self._store = ConnectionStore()

        self._id = self._store.resolve(
            connection=connection,
            connection_id=connection_id,
        )

    @property
    def id(self) -> str:
        """
        age-oauth connection ID
        """
        return self._id

    @property
    def meta(self) -> ConnectionMeta:
        """
        current metadata for connection
        """
        meta = self._store.load_meta(self._id)

        if meta is None:
            raise RuntimeError(
                f"Connection metadata not found for connection_id={self._id!r}"
            )

        return meta

    @property
    def label(self) -> str:
        """
        friendly connection label
        """
        return self.meta.label

    @property
    def portal_url(self) -> str:
        """
        ArcGIS Enterprise Portal URL
        """
        return self.meta.portal_url

    @property
    def auth_type(self) -> str:
        """
        auth type for this connection ('user' or 'app')
        """
        return self.meta.auth_type

    def get_gis(
        self,
        *,
        prompt_if_missing: bool = True,
    ):
        """
        returns an injected arcgis.gis.GIS to work with
        """
        # Import locally to keep the connection abstraction lightweight and
        # avoid introducing unnecessary module-level coupling.
        from .oauth import get_gis

        return get_gis(
            connection_id=self._id,
            prompt_if_missing=prompt_if_missing,
        )

    def get_identity(self, gis):
        """
        resolve the authenticated user or app identity for this connection
        """
        from .oauth import resolve_identity

        return resolve_identity(gis, connection_id=self._id)

    def __repr__(self) -> str:
        try:
            meta = self.meta
            return (
                f"Connection("
                f"label={meta.label!r}, "
                f"id={self._id!r}, "
                f"portal_url={meta.portal_url!r}, "
                f"auth_type={meta.auth_type!r}"
                f")"
            )
        except Exception:
            return f"Connection(id={self._id!r})"