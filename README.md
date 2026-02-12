# age-oauth

ArcGIS Enterprise OAuth helper with per-user, multi-portal credential and token cache

`age-oauth` lets you store OAuth client settings for multiple ArcGIS Enterprise portals, pick one by label or ID, and then

* authenticate interactively and cache tokens
* create an `arcgis.gis.GIS` object programmatically using cached credentials

## Install (local)

`pip install --user .`

## Install options

Minimal

`pip install age-oauth`

With ArcGIS support if it's not already there:

`pip install "age-oauth[arcgis]"`

With arcgis-mapping support too:

`pip install "age-oauth[mapping]"`

With everything

`pip install "age-oauth[full]"`


## ArcGIS Pro desktop users

If you're using the default `arcgispro-py3` environment that ships with ArcGIS Pro:

**You must have an active ArcGIS Pro license session before using the `arcgis` Python API.**

This usually means launching ArcGIS Pro once and signing in before running `age-oauth` or other scripts that import `arcgis.gis`.

This is a licensing requirement enforced by Esri and is not specific to `age-oauth`.

## Authenticate (command line)

`age-oauth login`

to verify:

`age-oauth whoami`

## Token storage

Connection profiles and OAuth tokens are stored per-user under your OS config directory

Windows:

`%APPDATA%\age_oauth\`

macOS/Linux:

`~/.config/age_oauth/`

Each saved connection contains a `.env` (OAuth settings and tokens), and a `.meta.json` (connection metadata)

## How to...

### Add a portal to your stash

Interactively (recommended):

`age-oauth connections add`

You will be prompted for:

* Connection label (short human readable name for the portal, e.g. `prod`)
* Portal URL (e.g., `https://mydomain.com/portal`)
* Verify SSL (`true`, `false`, or a path to a custom CA bundle)
* OAuth client ID
* OAuth client secret

The script will then guide you through a browser confirmation to obtain an authorization code, and proceed.

To list connections:

`age-oauth connections list`

To set an active connection:

`age-oauth connections use prod` (or use the connection id in `connections list`)

### Log in to a specific portal from the command line

Login to the active/default portal:

`age-oauth login`

Login to specific portal by label or id:

`age-oauth login --connection prod`

Confirm which user you're authenticated as:

`age-oauth whoami --connection prod`

### Use get_gis() programmatically in a script

Minimal example:

```
from age_oauth import get_gis

# uses active/default connection resolution rules
gis = get_gis()

print(gis.properties.portalName)
print(gis.users.me.username)
```

Select a specific portal by label (or connection id):

```
from age_oauth import get_gis

gis = get_gis(connection="prod")
print(gis.users.me.username)
```

If you want scripts to fail fast with no interactive prompts:

```
from age_oauth import get_gis

# will raise if the connection is missing required settings instead of prompting
gis = get_gis(connection="prod", prompt_if_missing=False)
```

### Connection selection rules

when you call `get_gis()` (or use CLI with `--connection`), `age-oauth` resolves which portal to use in the following order:

1. explicit `connection_id`
2. connection selector
    * exact ID match, else
    * exact label match, else
    * unique id prefix match
3. active connection
4. default connection
5. if there's only one connection, use that

### SSL verification stuff

`OAUTH_VERIFY_SSL` (or CLI with `--verify-ssl`) supports...

* `true`
* `false`
* `/path/to/custom/cert authority bundle`

### License

AGPL-3.0-or-later