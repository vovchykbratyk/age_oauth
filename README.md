# age-oauth

`age-oauth` is a convenience package which makes it easier for script users to interact with an ArcGIS Enterprise by simplifying the OAuth 2.0 process, and eliminating the need (and bad security practice) of having to store username/passwords in your scripts.

## Install

**NOTE**: You must have `arcgis` installed in your desired Python environment.  If you want the full capabilities of ArcGIS API for Python, go ahead and install `arcgis-mapping` too.  If you're working with ArcGIS Pro, these are already available to you in `arcgispro-py3` and any cloned environments.  Otherwise grab them from either Esri's conda channel (recommended):

```
conda install -c esri arcgis arcgis-mapping
```
or pip:

```
pip install arcgis arcgis-mapping
```

Then [Grab the latest `.whl`.](/owner/repo/releases/latest)

In your desired Python environment, do:

`pip install <path to wheel file>` or `pip install --user <path to wheel file>`


## Usage

### Step 0: Prereqs

This README presumes you already have the needed permissions to have created a valid set of OAuth 2.0 app/developer tokens on a target ArcGIS Enterprise system. You should have ready:

* the Portal root URL (e.g., `https://somwhere.com/portal`)
* OAuth2 client ID
* OAuth2 client secret
* The app's Redirect URI set to `urn:ietf:wg:oauth:2.0:oob` (Esri's default out of band URI)

### Step 1: Add a Portal to your local store

Run:

```powershell
age-oauth connections add
```

You'll be prompted for the following:

```powershell
Connection label:        <short, plain language name to identify portal, no spaces>
Portal URL:              https://somewhere.com/portal
Verify SSL:              false, true, or path to custom CA cert
OAuth Client ID:         <your client ID>
OAuth Client Secret:     <your client secret>
```

When it's done, you'll see:

```powershell
[OK] Created connection: my_portal
```

#### Step 1.a: Add the Portal non-interactively

You can also add the Portal non-interactively.  Assuming a PowerShell environment:

```powershell
age-oauth connections add `
  --label "Prod" `
  --portal "https://somewhere.com/portal" `
  --verify-ssl false `
  --client-id "client_id_value" `
  --client-secret "client_secret_value"
```

### Step 2: Authenticate / Onboard

Now we'll authenticate for the first time (interactively, from CLI)

```powershell
age-oauth login --connection my_portal
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
age-oauth whoami --connection my_portal
```

You should see:

```powershell
your.username
```

Your OAuth credentials are now onboarded and you can proceed to use it programmatically.

### Step 4: Programmatic use

Now, you can use it in Python:

```python
from age_oauth import get_gis

gis = get_gis(connection="my_portal")

# verify
print(gis.properties.portalName)
print(gis.users.me.username)
```

No username/passwords, no tokens, no PKI decryption in your scripts. `age-oauth` handles negotiation and refresh automatically.

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