# age-oauth

`age-oauth` simplifies access to an ArcGIS Enterprise via OAuth 2.0 credentials (application or user), and eliminates the need (and bad security practice) of storing username/passwords/tokens in your scripts.  `age-oauth` also stores and indexes multiple connection profiles - these connections could be different scopes on the same Portal, or multiple Portals, or a combination of the two.  Moreover, multiple connections can be used in any automation by simply calling them by their storage label.

## Pre-Requisites and OAuth 2.0 Item Creation

This README assumes that you already have the permissions needed to create OAuth 2.0 app/developer tokens on an ArcGIS Enterprise instance.

`age-oauth` supports two paths for OAuth 2.0; **user** and **application**.

| Auth type | Use when you need to... | OAuth flow
|---|---|---
|`user` | access assets as yourself | auth code + refresh token
|`application` | access assets as an application | client credentials

If you are creating an OAuth item and do not have your own web server (e.g., you're just running manual or automated scripts), you will need to use either an out-of-band (OOB) URI for the redirect value (for **user** auth type) or a dummy referrer value (for **app** auth type) when prompted:

Default OOB URI (user): `urn:ietf:wg:oauth:2.0:oob`
Dummy referrer (app): `https://localhost`

### Application Permissions

On ArcGIS Enterprise 11.4+, OAuth 2.0 App credentials can be configured with application permissions, or depending on Portal configuration and the privileges of the creating user, it could be set to impersonate the user.  **Please verify the permissions you give the application in ArcGIS Enterprise and coordinate with your administrators before using it for unattended automation.  You've been warned!**

## Install

Use `pip` to install `age-oauth`.

### Minimal

This is fine if you're installing into an ArcGIS Pro conda environment, e.g. `arcgispro-py3` or if you don't need the `arcgis` package.

```
python -m pip install age-oauth
```

### Full

This will install `arcgis` and `arcgis-mapping` and give you full **ArcGIS API for Python** access.

```
python -m pip install "age-oauth[full]"
```

## Use

### Add a Connection

Connections are added via CLI, and can be created interactively or non-interactively.

#### Add Connection Interactively

Run:

```powershell
age-oauth connections add
```

You'll be prompted for the connection settings, including whether the connection authenticates as a **user** or as an **application**.

Connections are given a friendly label so scripts can refer to them without embedding portal URLs, client IDs, secrets, or tokens.


#### Add Connection Non-interactively

You can also add the Portal non-interactively.  For a new **user** connection type:

```powershell
age-oauth connections add `
  --label "some user" `
  --portal "https://somewhere.com/portal" `
  --auth-type user `
  --verify-ssl false `
  --client-id "client_id_value" `
  --client-secret "client_secret_value"
```

For a new **application** credential:

```powershell
age-oauth connections add `
  --label "some app" `
  --portal "https://somewhere.com/portal" `
  --auth-type app `
  --referer "https://localhost" `
  --verify-ssl true `
  --client-id "client_id_value" `
  --client-secret "client_secret_value"
```

#### Private/Custom CAs

**NOTE:** If your ArcGIS Enterprise uses a private CA, you can pass the CA's path to `--verify-ssl`.

### First Authentication / Onboarding

**User** and **application** OAuth credential types are logged in the same way.  For a **user** connection profile, a browser challenge-response will be presented.

```powershell
age-oauth login --connection "some user"
```

You'll see:

```powershell
Opening browser for ArcGIS Enterprise OAuth sign-in...
```

A browser will open to your Portal login screen.  Sign in, grab the **authorization code** and paste it back into the shell where you are being prompted for it.

`age-oauth` will swap the authorization code for an **access token**, a **refresh token**, and an **expiration timestamp**. This is then securely stored in your user profile. If all is successful, you'll see:

```powershell
New access_token acquired!  Expires in: 2:00:00
Token is for user: your.username
```

For **application** connection profiles, `age-oauth` will cache, access and fetch new access tokens as needed in accordance with a Portal's expiration policy.

### Validate Connection and Identity

To verify, do:

```powershell
age-oauth whoami --connection "some user"
```

In the case of a **user** you should see:

```powershell
your.username
```

In the case of an **application**, you should see:

```powershell
Type:        application
Application: Application Name
App ID:      XXXXXXXXXXXXXXXX
Item ID:     XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Owner:       your.username
```

Your OAuth credentials are now onboarded and you can start using them programmatically.

### Python API

Now, you can use it in Python!

```python
from age_oauth import Connection, list_connections

# Create an authenticated arcgis.gis.GIS object by label
portal_conn = Connection(connection="connection label")
gis = portal_conn.get_gis()

# Create an authenticated session by index
portal_conns = list_connections()
print(portal_conns)

# result
#	['some user', 'some application', 'another connection']

# Initialize multiple Connection objects in the same script

my_conns = {
    conn.label: conn.get_gis()
    for conn in list_connections()
}

user_conn = my_conns["some user"]
app_conn = my_conns["some application"]
```

No username/passwords, no tokens, no janky PKI decryption in your scripts. `age-oauth` handles negotiation and refresh automatically.

### Rotation of refresh_token for user access

While calling the library programmatically will automatically update the `refresh_token` associated with the active connection automatically (3 day duration), users or admins can also call it interactively.

```
age-oauth token --rotate-refresh-token --portal <portal label>
```

If the `refresh_token` is still good, the command does nothing.


## Storage

Portal profiles are stored per-user under your OS home (profile) directory. Nothing is stored globally:

Windows

```
%APPDATA%\age_oauth\
```

Each connection contains the following:

```
connections/
    my_portal_<uuid>/
        .env         # OAuth settings and tokens
        meta.json    # metadata
```

## Why does this exist?

It is tempting to write scripts like:

```python
gis = GIS("https://my-portal.com/portal", "username", "password")

# or

gis = GIS("https://my-portal.com/portal", token="abcdef12345abcdef12345abcdef...")
```

Or do any number of other sketchy things.  This creates both security and maintainability problems, with increased technical debt at best and compromise at worst.

In a secure setting, we want revocable credentials, clear ownership of the access object, an expiration policy and centralized management.  This is exactly what the OAuth workflow gives you when it's properly used.

`age-oauth` is designed to make this way (the more secure way) also the more convenient way.

### But why not just use API keys?

ArcGIS Enterprise developer API keys are useful, but they have short lifetimes and require manual renewal. This introduces friction into automations you may need to run under your human-user persona. OAuth supports refresh tokens that can be reused indefinitely to get new access tokens. Going through the up-front setup to establish OAuth client access pays off in the long run by giving you way cleaner scripts that are easier to maintain, can be passed around without fear of leaking your credentials, and helps your security folks sleep better at night.
