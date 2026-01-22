## Install (local)

```
pip install --user .
```

### Install Options

Minimal:

```
pip install age-oauth
```

With `arcgis-mapping` support:

```
pip install "age-oauth[mapping]"
```

Full install (with `arcgis-mapping` and `dotenv` convenience):

```
pip install "age-oauth[full]"
```

## Login (writes per-user token cache)

```
age-oauth --whoami
```

## Token management
Token cache stored at `~/.arcgis/.env` (override with `ARCGIS_USER_ENV`)
