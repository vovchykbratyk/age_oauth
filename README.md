# age-oauth

`age-oauth` is a convenience package which makes it easier for script users to interact with ArcGIS Enterprise by simplifying the OAuth 2.0 process, and eliminating the need (and bad security practice) of having to store username/passwords in your scripts.  `age-oauth` supports the storage of multiple connections - this could be different scopes on the same Portal, or multiple Portals, or a combination of the two.  Moreover, multiple connections can be used in any automation by simply calling them by their storage label.

## Install

Minimal (fine if you're installing into an ArcGIS Pro conda environment, e.g. `arcgispro-py3` or clones):

```
python -m pip install age-oauth
```

Full dependencies (installs `arcgis` and `arcgis-mapping`):

```
python -m pip install "age-oauth[full]"
```


## Usage

### Step 0: Prereqs

This README presumes you already have the needed permissions to have created a valid set of OAuth 2.0 app/developer tokens on a target ArcGIS Enterprise system. There are two paths that `age-oauth` supports:

| authentication type | use when | OAuth flow
|---|---|---
|`user` | access assets as yourself | auth code + refresh token
|`application` | access assets as an application | client credentials

In either case, you'll need:
* the Portal root URL (e.g., `https://somwhere.com/portal`)
* OAuth2 client ID
* OAuth2 client secret

For **user authentication** you are going to need an out-of-band URI for redirect when you create the credentials in ArcGIS Enterprise, if you're not creating a web app with a server:

```urn:ietf:wg:oauth:2.0:oob```

For **application authentication** no user redirect or browser challenge is required.  Depending on the ArcGIS Enterprise config, you might need to supply the HTTP referer associated with the application. If it's just a script with no web server, just use `https:\\localhost`.

### Step 0.1: PERMISSIONS

Permissions matter - app credentials can be configured with application permissions, or depending on Portal configuration and the privileges of the creating user, it could be set to impersonate the user.  Please verify the permissions you give the application in ArcGIS Enterprise and square this all away with your cybersecurity folks before using it for unattended automation.  You've been warned!

### Step 1: Add a connection

Run:

```powershell
age-oauth connections add
```

You'll be prompted for the connection settings, including whether the connection authenticates as a **user** or as an **application**.

Connections are given a friendly label so scripts can refer to them without embedding portal URLs, client IDs, secrets, or tokens.


#### Step 1.a: Add the Portal non-interactively

You can also add the Portal non-interactively.  Assuming a PowerShell environment and a **user** credential:

```powershell
age-oauth connections add `
  --label "some user" `
  --portal "https://somewhere.com/portal" `
  --auth-type user `
  --verify-ssl false `
  --client-id "client_id_value" `
  --client-secret "client_secret_value"
```
If your ArcGIS Enterprise uses a private CA, you can pass the CA's path to `--verify-ssl` instead.

Assuming an **application** credential, it would be done like this:

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


### Step 2: Authenticate / Onboard

Now we'll authenticate for the first time (interactively, from CLI).  We'll use a **user** auth type for example - **application** auth types are handled in the same way, except without the browser challenge.

```powershell
age-oauth login --connection "some user"
```

You'll see:

```powershell
Opening browser for ArcGIS Enterprise OAuth sign-in...
```

A browser will open to your Portal login screen. You need to:

1. Sign in
2. Portal displays an authorization code
3. Copy the code
4. Paste it back into the terminal where you are being prompted for it

`age-oauth` will swap the authorization code for an **access token**, a **refresh token**, and an **expiration timestamp**. This is then securely stored in your user profile. If all is successful, you'll see:

```powershell
New access_token acquired!  Expires in: 1:00:00
Token is for user: your.username
```

### Step 3: Confirm authentication

To verify, do:

```powershell
age-oauth whoami --connection "some user"
```

You should see:

```powershell
your.username
```

Your OAuth credentials are now onboarded and you can proceed to use it programmatically.

### Step 4: Programmatic use

Now, you can use it in Python!

```python
from age_oauth import get_gis

gis = get_gis(connection="some user")

# verify
print(gis.properties.portalName)
print(gis.users.me.username)
```
No username/passwords, no tokens, no PKI decryption in your scripts. `age-oauth` handles negotiation and refresh automatically.


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

Or do any number of other sketchy things like -

* usernames/passwords in `.py` or sidecar files
* decrypt PKI client certs into unencrypted, plain-text `.pem` files
* copy static access tokens from a browser
* paste your API keys right into scripts

All of these practices create both security and maintainability problems, with compromise at worst and increased technical debt at best. In a secure setting, we're going for:

* credentials that can be revoked
* clear ownership of access
* clear expiration policy
* centralized control

This is exactly what the OAuth workflow gives you when it's properly used. You have to authenticate via Portal. A short-lived `access_token` is issued (expiration and rotation policy). A longer-lived `refresh_token` can renew access automatically once the "app" is authorized. These tokens can then be revoked via Portal (centralization). So while nothing's perfect, this workflow aligns much better with typical enterprise security expectations.

`age-oauth` is designed to make the more secure way also the more convenient way. It will give you:

* A per-user connection store to manage multiple Portal connections
* OAuth client configuration per Portal
* Automatic token refresh
* A simple, injected `arcgis.gis.GIS` class object instantiated via `age_oauth.get_gis()`

### But why not just use API keys?

ArcGIS Enterprise developer API keys are useful, but they have short lifetimes and require manual renewal. This introduces friction into automations you may need to run under your human-user persona. OAuth supports refresh tokens that can be reused indefinitely to get new access tokens. Going through the up-front setup to establish OAuth client access pays off in the long run by giving you way cleaner scripts that are:

* more easily maintained,
* can be passed around without fear of accidentally leaking credentials,
* better aligned with enterprise security and therefore help everyone sleep better at night.