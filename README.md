# IBM Verify Python SDK

[![PyPI version](https://img.shields.io/badge/pypi-v0.1.0-blue.svg)](https://pypi.org/project/verify-auth-python/)
[![Build Status](https://img.shields.io/badge/build-lint%20warnings-yellow.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://pypi.org/project/verify-auth-python/)

A Python SDK for IBM Verify SaaS, focused on OAuth 2.0 and OIDC - token acquisition, discovery, introspection, and dynamic client registration.

IBM Verify solves hybrid challenges with secure, frictionless IAM that simplifies identity and strengthens your identity fabric—without burdening admins. Learn more about [IBM Verify](https://www.ibm.com/products/verify) and sign up for a free SaaS tenant.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [OAuthClient](#oauthclient)
  - [Construction](#construction)
  - [Discovery](#discovery)
  - [extra\_params](#extra_params)
  - [authorization\_details](#authorization_details)
  - [client\_credentials()](#client_credentials)
  - [password\_grant()](#password_grant)
  - [build\_authorization\_url() / exchange\_code\_for\_token()](#build_authorization_url--exchange_code_for_token)
  - [request\_device\_code() / poll\_device\_token() / device\_authorization\_flow()](#request_device_code--poll_device_token--device_authorization_flow)
  - [token\_exchange()](#token_exchange)
  - [jwt\_bearer\_grant()](#jwt_bearer_grant)
  - [refresh\_access\_token()](#refresh_access_token)
  - [introspect\_token()](#introspect_token)
  - [DPoP (RFC 9449)](#dpop-rfc-9449)
  - [Dynamic Client Registration (DCR)](#dynamic-client-registration-dcr)
  - [Utility functions](#utility-functions)
- [Exception Handling](#exception-handling)
- [SDK Modules](#sdk-modules)
- [Project Structure](#project-structure)
- [Development](#development)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [Support](#support)
- [License](#license)

---

## Requirements

- Python 3.9+
- An IBM Verify tenant

---

## Installation

```bash
pip install verify-auth-python
```

```bash
uv add verify-auth-python
```

For local development using the repository source code directly (without installing from PyPI), see [Development](#development).

---

## OAuthClient

`OAuthClient` is the single entry point for all token-acquisition operations.

```python
from ibm_verify.oauth2.auth.client import OAuthClient
```

### Construction

```python
client = OAuthClient(
    base_url="https://your-tenant.verify.ibm.com",  # required
    timeout=30,                                      # optional, seconds (default 30)
    verify_ssl=True,                                 # optional (default True)
    token_endpoint=None,                             # optional — overrides discovery + default path
    introspect_endpoint=None,                        # optional — overrides discovery + default path
    client_cert=None,                                # optional — path string or (cert, key) tuple for mTLS
    client_key=None,                                 # optional — key path when client_cert is cert-only
)
```

`OAuthClient` implements the context manager protocol:

```python
with OAuthClient(base_url="https://your-tenant.verify.ibm.com") as client:
    client.load_discovery()
    token = client.client_credentials(...)
```

### Discovery

Endpoint resolution priority for every grant method: **caller argument → constructor override → discovery → built-in default**.
Call `load_discovery()` after constructing an `OAuthClient` instance to populate endpoints automatically.

```python
metadata = client.load_discovery(
    op_name="default",       # optional OIDC provider name (default: "default")
    discovery_url=None,      # optional explicit discovery URL override
)
# Returns: OpenIDProviderMetadata populated with endpoint URLs
```

```python
metadata = client.get_discovery()   # returns cached metadata; fetches if not yet loaded
```

```python
jwks = client.get_jwks(
    op_name="default",   # optional
    jwks_uri=None,       # optional explicit JWKS URI override
)
# Returns: JWKS document dict
```

---

### extra_params

Every grant method accepts an `extra_params` dictionary (a key-value mapping of parameter names to values) that is merged verbatim into the request body. Use it to pass non-standard or tenant-specific parameters without subclassing.

```python
# Pass a custom IBM Verify claim and an audience restriction in a client_credentials call
token = client.client_credentials(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    scope="openid",
    authorization_header="Basic ...",
    extra_params={
        "audience": "https://api.example.com",
        "resource": "urn:example:resource",
    },
)
```

The same pattern applies to `password_grant()`, `exchange_code_for_token()`, `refresh_access_token()`, `token_exchange()`, `jwt_bearer_grant()`, `request_device_code()`, `device_authorization_flow()`, and all other methods that accept `extra_params`.

---

### authorization_details

`authorization_details` implements Rich Authorization Requests (RAR, [RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396)). Pass a list of authorization detail objects - the SDK JSON-encodes them automatically before sending.

```python
# Request a payment initiation scope with fine-grained authorization details
token = client.client_credentials(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    scope="openid",
    authorization_header="Basic ...",
    authorization_details=[
        {
            "type": "payment_initiation",
            "locations": ["https://payments.example.com/accounts"],
            "instructed_amount": {
                "currency": "USD",
                "amount": "150.00",
            },
            "creditor_account": {"iban": "DE02100100109307118603"},
        }
    ],
)
```

The resulting token request body contains:

```
authorization_details=[{"type":"payment_initiation","locations":[...],...}]
```

The same parameter is accepted by every grant method that supports RAR: `password_grant()`, `exchange_code_for_token()`, `build_authorization_url()`, `request_device_code()`, `device_authorization_flow()`, `token_exchange()`, `jwt_bearer_grant()`, and `refresh_access_token()`.

---

### client_credentials()

```python
token = client.client_credentials(
    client_id="YOUR_CLIENT_ID",              # required
    client_secret="YOUR_CLIENT_SECRET",      # optional — omit when using private_key_jwt
    scope="openid",                          # optional — space-separated scopes
    authorization_header=None,               # optional — pre-encoded header, used only when no secret/assertion is given
    token_endpoint=None,                     # optional endpoint override
    authorization_details=None,              # optional — list/dict, JSON-encoded automatically (RFC 9396)
    extra_params=None,                       # optional — dict merged into the token request body
    client_assertion=None,                   # optional — JWT string or callable for private_key_jwt auth
    client_assertion_type=None,              # optional — defaults to the jwt-bearer URN
    client_secret_post=False,                # optional — send client_secret in the body instead of Basic header
    dpop_private_key=None,                   # optional — PEM key to request a DPoP-bound token (RFC 9449)
)
# Returns: dict — access_token, token_type, expires_in, scope, …
```

The SDK selects the authentication method for you based on what you provide: a `client_assertion` (key-based, no secret) takes priority, then `client_secret`, then a pre-built `authorization_header`. You must supply at least one.

---

#### Authenticating without a client secret — private_key_jwt

By default, your app proves its identity with a `client_secret` — a shared password that lives in config files and CI pipelines. **private_key_jwt** replaces that password with a short-lived, digitally signed token. Your app keeps a private key; IBM Verify stores only the matching public key. Nothing sensitive ever travels over the network.

**One-time IBM Verify setup**

Go to your application → **Sign-on** tab → set **Client authentication method** to *Private key JWT* → upload your certificate or provide a JWKS URI.

**Using it in code**

```python
# Step 1 — build a signed, single-use token that proves who your app is.
# Generate a fresh one for every request — each is only valid for 5 minutes.
assertion = OAuthClient.generate_client_assertion_jwt(
    client_id="YOUR_CLIENT_ID",
    token_endpoint=client.get_discovery()["token_endpoint"],
    private_key=open("client-private.pem").read(),
    key_id="my-key",          # label of the key you registered on IBM Verify
)

# Step 2 — use it instead of client_secret.
token = client.client_credentials(
    client_id="YOUR_CLIENT_ID",
    scope="openid",
    client_assertion=assertion,   # no client_secret needed
)
```

The same `client_assertion=` parameter works on `exchange_code_for_token()`, `refresh_access_token()`, `jwt_bearer_grant()`, and `introspect_token()` — no client secret anywhere in the chain.

**Using it together with DPoP**

When DPoP is also enabled on the application, pass a function instead of a fixed string. The SDK may need to retry the request with a server nonce, and a function lets it generate a brand-new assertion for that retry:

```python
token = client.client_credentials(
    client_id="YOUR_CLIENT_ID",
    scope="openid",
    client_assertion=lambda: OAuthClient.generate_client_assertion_jwt(
        "YOUR_CLIENT_ID", token_endpoint, private_key, key_id="my-key"
    ),
    dpop_private_key=dpop_key,
)
```

---

### password_grant()

```python
token = client.password_grant(
    client_id="YOUR_CLIENT_ID",              # required
    client_secret="YOUR_CLIENT_SECRET",      # required
    username="user@example.com",             # required
    password="...",                          # required
    authorization_header="",                 # pre-encoded header; used only if client_secret is empty
    scope=None,                              # optional — space-separated scopes
    token_endpoint=None,                     # optional endpoint override
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
)
# Returns: dict — access_token, token_type, expires_in, scope, …
```

---

### build_authorization_url() / exchange_code_for_token()

**Step 1 — generate a PKCE pair and build the redirect URL:**

```python
code_verifier, code_challenge = OAuthClient.generate_pkce_pair()
# Returns: (code_verifier, code_challenge) — both URL-safe base64 strings

auth_url = client.build_authorization_url(
    client_id="YOUR_CLIENT_ID",              # required
    redirect_uri="https://app/callback",     # required
    code_challenge=code_challenge,           # required — S256 challenge from generate_pkce_pair()
    scope="openid profile email",            # optional (default: "openid profile email")
    state=None,                              # optional — auto-generated if omitted
    nonce=None,                              # optional
    authorize_endpoint=None,                 # optional endpoint override
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
    dpop_jkt=None,                           # optional — DPoP key thumbprint; binds the code to the key (RFC 9449 §10)
)
# Returns: str — authorization URL to redirect the user's browser to
```

**Step 2 — exchange the returned code for tokens:**

```python
token = client.exchange_code_for_token(
    client_id="YOUR_CLIENT_ID",              # required
    redirect_uri="https://app/callback",     # required — must exactly match Step 1
    code="RETURNED_CODE",                    # required — authorization code from the redirect callback
    code_verifier=code_verifier,             # required — verifier from generate_pkce_pair()
    client_secret=None,                      # optional — confidential clients (client_secret_post)
    client_assertion=None,                   # optional — JWT for private_key_jwt auth
    client_assertion_type=None,              # optional — URN; required when client_assertion is set
    token_endpoint=None,                     # optional endpoint override
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
)
# Returns: dict — access_token, id_token, token_type, expires_in, …
```

---

### request_device_code() / poll_device_token() / device_authorization_flow()

**Step 1 — request a device code:**

```python
device_data = client.request_device_code(
    client_id="YOUR_CLIENT_ID",              # required
    scope="openid profile email",            # optional (default: "openid profile email")
    client_secret=None,                      # optional — confidential clients only
    device_auth_endpoint=None,               # optional endpoint override
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
)
# Returns: dict — device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval
```

**Step 2 — poll until approved (blocks):**

```python
token = client.poll_device_token(
    client_id="YOUR_CLIENT_ID",              # required
    device_code=device_data["device_code"],  # required — from request_device_code()
    interval=device_data.get("interval", 5), # optional — poll interval in seconds (default: 5)
    expires_in=device_data.get("expires_in", 300),  # optional — deadline in seconds (default: 300)
    client_secret=None,                      # optional — confidential clients only
    token_endpoint=None,                     # optional endpoint override
    extra_params=None,                       # optional
)
# Returns: dict — access_token, id_token, token_type, expires_in, …
# Raises: VerifyError — on expired_token, access_denied, or network error
```

**Convenience wrapper — runs both steps:**

```python
token = client.device_authorization_flow(
    client_id="YOUR_CLIENT_ID",              # required
    scope="openid profile email",            # optional (default: "openid profile email")
    client_secret=None,                      # optional
    device_auth_endpoint=None,               # optional endpoint override
    token_endpoint=None,                     # optional endpoint override
    on_user_code=lambda d: print(d["verification_uri_complete"]),  # optional callback
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
)
# Returns: dict — access_token, id_token, token_type, expires_in, …
```

---

### token_exchange()

```python
token = client.token_exchange(
    client_id="YOUR_CLIENT_ID",              # required
    client_secret="YOUR_CLIENT_SECRET",      # required
    subject_token="SUBJECT_TOKEN",           # required — token representing the subject
    actor_token="ACTOR_TOKEN",               # required — token representing the acting party
    token_endpoint=None,                     # optional endpoint override
    subject_token_type="urn:ietf:params:oauth:token-type:access_token",  # optional
    actor_token_type="urn:ietf:params:oauth:token-type:access_token",    # optional
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
)
# Returns: dict — access_token, token_type, expires_in, …
```

---

### jwt_bearer_grant()

Build the assertion with [`generate_jwt_bearer_assertion()`](#utility-functions), then pass it here.

```python
token = client.jwt_bearer_grant(
    assertion="SIGNED_JWT",                  # required — from generate_jwt_bearer_assertion()
    client_id="YOUR_CLIENT_ID",              # optional
    client_secret=None,                      # optional — client_secret_post auth
    scope=None,                              # optional — space-separated scopes
    token_endpoint=None,                     # optional endpoint override
    client_assertion=None,                   # optional — JWT for private_key_jwt client auth
    client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",  # optional
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
)
# Returns: dict — access_token, token_type, expires_in, …
```

---

### refresh_access_token()

```python
token = client.refresh_access_token(
    client_id="YOUR_CLIENT_ID",              # required
    refresh_token="REFRESH_TOKEN",           # required
    client_secret=None,                      # optional — HTTP Basic by default
    client_secret_post=False,                # optional — send the secret in the body instead
                                             #   (IBM Verify apps limited to client_secret_post
                                             #    reject Basic with CSIAQ0330E, e.g. device clients)
    client_assertion=None,                   # optional — JWT for private_key_jwt auth
    client_assertion_type=None,              # optional — URN; required when client_assertion is set
    scope=None,                              # optional — must be a subset of the original grant
    token_endpoint=None,                     # optional endpoint override
    authorization_details=None,              # optional (RFC 9396)
    extra_params=None,                       # optional
)
# Returns: dict — access_token, refresh_token, token_type, expires_in, …
```

---

### introspect_token()

```python
result = client.introspect_token(
    token="ACCESS_OR_REFRESH_TOKEN",         # required
    op_name="default",                       # optional OIDC provider name (default: "default")
    client_id=None,                          # optional
    client_secret=None,                      # optional
    client_assertion=None,                   # optional — JWT for private_key_jwt auth (sent with client_id)
    client_assertion_type=None,              # optional — defaults to the jwt-bearer URN
    token_type_hint=None,                    # optional — "access_token" or "refresh_token"
    authorization_header=None,               # optional — alternative to client_id/secret
    introspect_endpoint=None,                # optional endpoint override
)
# Returns: dict — active (bool), scope, client_id, username, exp, sub, iss, …
```

---

### DPoP (RFC 9449)

DPoP (Demonstrating Proof of Possession) binds an access token to a key pair that only the requesting client holds. A stolen token is useless without the matching private key.

DPoP is not a separate grant type — add `dpop_private_key` to any existing token call: `client_credentials()`, `exchange_code_for_token()`, `refresh_access_token()`, `password_grant()`, `token_exchange()`, `jwt_bearer_grant()`, `poll_device_token()` / `device_authorization_flow()`.

**IBM Verify setup:** Applications → your application → Sign-on → expand **Proof-of-Possession settings** → enable **Enforce DPoP-bound access token**. Note the **Signing algorithm for DPoP JWT** (default `RS256`) — your key type must match.

**Step 1 — Generate a key pair**

```python
# Keep this private key for the lifetime of the token. RSA (RS256) matches IBM Verify's default.
private_key = OAuthClient.generate_dpop_key_pair("RSA")   # or "EC" for ES256
```

**Step 2 — Request a DPoP-bound token**

```python
token = client.client_credentials(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    scope="openid",
    dpop_private_key=private_key,            # SDK attaches the DPoP proof header automatically
    dpop_algorithm=None,                     # optional — inferred from the key type if omitted
)
# token["token_type"] == "DPoP"
# token["access_token"] carries cnf.jkt — the thumbprint of your public key
```

**Step 3 — Call a DPoP-protected resource**

```python
# dpop_request() builds Authorization: DPoP + a fresh proof, and retries automatically
# if the resource server returns a use_dpop_nonce challenge.
response = client.dpop_request(
    "GET", "https://api.example.com/resource",
    access_token=token["access_token"],
    private_key=private_key,
)

# Or build the headers yourself (e.g. for use with another HTTP client):
headers = client.build_dpop_headers(
    access_token=token["access_token"],
    private_key=private_key,
    http_method="GET",
    http_url="https://api.example.com/resource",
)
# {"Authorization": "DPoP <token>", "DPoP": "<proof>"}
```

**Step 4 — Validate the proof on the resource server**

```python
from ibm_verify.oauth2.grant_types.dpop import InMemoryDPoPReplayCache

# Create replay_cache once per process. For multi-instance deployments use a shared
# store (e.g. Redis SET jti 1 NX EX <ttl>) implementing the same check_and_store() interface.
replay_cache = InMemoryDPoPReplayCache()

result = client.introspect_dpop_token(
    token=token["access_token"],
    dpop_proof=headers["DPoP"],
    http_method="GET",
    http_url="https://api.example.com/resource",
    replay_cache=replay_cache,               # rejects replayed proofs (RFC 9449 §11.1)
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
)
# Raises VerifyError if the proof signature, ath, htm/htu, iat window,
# cnf.jkt binding, or jti replay check fails.
```

**Nonce handling (automatic)**

If IBM Verify or the resource server requires a server-issued nonce (`400 use_dpop_nonce` or `401 WWW-Authenticate: DPoP error="use_dpop_nonce"`), the SDK retries the request once with the supplied nonce — no code changes needed. The nonce is cached per server origin for subsequent calls. If the retry also fails, `VerifyError.dpop_nonce` holds the latest server nonce for debugging.

**Other helpers**

`client.compute_dpop_jkt(private_key)` — returns the key thumbprint (`cnf.jkt`).
`client.generate_dpop_proof(...)` — builds a proof manually for custom flows.
`ibm_verify.oauth2.grant_types.dpop` — exports `verify_dpop_proof()`, `compute_ath()`, and `InMemoryDPoPReplayCache` for use in resource server code.

---

### Dynamic Client Registration (DCR)

IBM Verify supports [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) (OAuth 2.0 Dynamic Client Registration) and [RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592) (Dynamic Client Registration Management). These methods allow you to register, read, update, and delete OAuth clients programmatically at runtime without manual portal configuration.

```python
from ibm_verify.oauth2.auth.client import OAuthClient
```

Unlike the grant methods, the DCR methods take a single `client_metadata` dict rather than individual keyword arguments. This lets you pass through any field IBM Verify's registration endpoint accepts — standard RFC 7591 fields, OIDC fields (`jwks_uri`, `subject_type`, …), RAR (`authorization_details_types`), mTLS fields, or tenant-specific extensions — without the SDK needing to enumerate every one.

> **Token rotation:** IBM Verify rotates `registration_access_token` on every successful RFC 7592 call (`read_client`, `update_client`, `delete_client`). Always pass the token returned by the *most recent* call — not the original one from `register_client()` — into the next one. The following workflow example shows this in practice.

#### register_client()

Register a new OAuth client dynamically (RFC 7591). An initial access token (IAT) issued by IBM Verify authorizes the registration request — the parameter is optional at the SDK level, but most IBM Verify tenants require it.

> **IAT requirement:** If the DCR endpoint is configured as **public**, no IAT is required. If it is **not public**, an IAT access token must be provided — issued by an API client with the `manageOidcDynamicClient` entitlement enabled.

> **Getting an initial access token:** In the IBM Verify admin console, navigate to **Security → API Access → API clients**, create or select an API client that has the *Manage OAuth clients* entitlement, and generate an access token from it. That token is your IAT. It is a one-time-use credential that must be passed here — it is not an OAuth bearer token from your application.

```python
client_info = client.register_client(
    client_metadata={                              # required — dict of registration fields
        "client_name": "My App",
        "redirect_uris": ["https://app/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "openid profile email",
        # any additional fields IBM Verify's registration endpoint accepts, e.g.:
        # "jwks_uri": "https://app/jwks.json",
        # "authorization_details_types": ["payment_initiation"],
    },
    initial_access_token=None,                     # optional in the SDK, but required by most
                                                     # IBM Verify tenants to authorize registration
    registration_endpoint=None,                     # optional endpoint override — takes priority
                                                     # over discovery and the SDK default
)
# Returns: dict — client_id, client_secret, client_id_issued_at, client_secret_expires_at,
#                 registration_access_token, registration_client_uri, …
```

**Example:**

```python
client = OAuthClient(base_url="https://your-tenant.verify.ibm.com")

new_client = client.register_client(
    client_metadata={
        "client_name": "My Service",
        "redirect_uris": ["https://myapp.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "openid profile email",
        "token_endpoint_auth_method": "client_secret_basic",
    },
    initial_access_token="eyJhbGciOi...",
)

print(new_client["client_id"])     # use this in subsequent OAuth flows
print(new_client["client_secret"]) # store securely
# Save new_client["registration_access_token"] and new_client["registration_client_uri"]
# to manage the client later
```

---

#### read_client()

Read the current configuration of a registered client (RFC 7592 §4.1). Requires the `registration_access_token` and `registration_client_uri` from the most recent RFC 7592 response (see the preceding token rotation note).

```python
client_info = client.read_client(
    registration_access_token="REGISTRATION_ACCESS_TOKEN",  # required
    registration_client_uri="REGISTRATION_CLIENT_URI",      # required — from the registration response
)
# Returns: dict — full client metadata as stored by the authorization server,
#                 including a rotated registration_access_token
```

---

#### update_client()

Replace the configuration of a registered client (RFC 7592 §4.2 PUT). This is a full-document PUT, not a PATCH — supply the complete `client_metadata` dict (typically the metadata returned by `read_client()`, modified as needed), since omitted fields may be cleared by the server.

```python
updated = client.update_client(
    registration_access_token="REGISTRATION_ACCESS_TOKEN",  # required — latest token
    registration_client_uri="REGISTRATION_CLIENT_URI",      # required
    client_metadata={                                       # required — full metadata document
        "client_name": "My App (updated)",
        "redirect_uris": ["https://app/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "openid profile email",
        # include any other fields returned by read_client() that should be preserved
    },
)
# Returns: dict — updated client metadata, including a rotated registration_access_token
```

---

#### delete_client()

Permanently remove a registered client (RFC 7592 §4.3 DELETE).

```python
client.delete_client(
    registration_access_token="REGISTRATION_ACCESS_TOKEN",  # required — latest token
    registration_client_uri="REGISTRATION_CLIENT_URI",      # required
)
# Returns: None — raises VerifyError on failure
```

---

#### DCR workflow example

```python
from ibm_verify.oauth2.auth.client import OAuthClient

oauth = OAuthClient(base_url="https://your-tenant.verify.ibm.com")
oauth.load_discovery()

# 1. Register
reg = oauth.register_client(
    client_metadata={
        "client_name": "My Dynamic App",
        "redirect_uris": ["https://myapp.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "openid profile email",
    },
    initial_access_token="<IAT from IBM Verify>",
)
client_id     = reg["client_id"]
client_secret = reg["client_secret"]
rat           = reg["registration_access_token"]   # rotates after every RFC 7592 call
reg_uri       = reg["registration_client_uri"]

# 2. Read back — note the rotated token in the response
info = oauth.read_client(registration_access_token=rat, registration_client_uri=reg_uri)
rat = info["registration_access_token"]             # always use the latest token

# 3. Update (full document PUT — start from the metadata read_client() returned)
info["redirect_uris"].append("https://myapp.example.com/callback2")
updated = oauth.update_client(
    registration_access_token=rat,
    registration_client_uri=reg_uri,
    client_metadata=info,
)
rat = updated["registration_access_token"]          # rotates again

# 4. Delete when no longer needed
oauth.delete_client(registration_access_token=rat, registration_client_uri=reg_uri)
```

---

### Utility functions

The following token and cryptography helper functions are available as `OAuthClient` static methods or as standalone imports from `ibm_verify.oauth2.grant_types.utils`:

- **`generate_pkce_pair()`** — generates a PKCE code verifier and challenge pair for authorization code flows
- **`generate_client_assertion_jwt()`** — creates a signed JWT for `private_key_jwt` client authentication
- **`generate_jwt_bearer_assertion()`** — creates a signed JWT assertion for the JWT Bearer grant

**Generate a PKCE pair:**

```python
code_verifier, code_challenge = OAuthClient.generate_pkce_pair()
# Returns: (code_verifier: str, code_challenge: str) — URL-safe base64, S256
```

**Generate a JWT for `private_key_jwt` client authentication:**

```python
client_assertion = OAuthClient.generate_client_assertion_jwt(
    client_id="YOUR_CLIENT_ID",              # required — used as iss and sub claims
    token_endpoint="https://…/token",        # required — used as aud claim
    private_key="PEM_STRING",                # required — PEM-encoded RSA or EC private key
    algorithm="RS256",                       # optional (default: "RS256")
    expires_in=300,                          # optional — JWT lifetime in seconds (default: 300)
    key_id=None,                             # optional — kid header
    audience=None,                           # optional — str or list; defaults to token_endpoint
)
# Returns: str — signed JWT for use as client_assertion
# Raises: ValueError — invalid key or unsupported algorithm
```

**Generate a JWT assertion for the JWT Bearer grant:**

```python
assertion = OAuthClient.generate_jwt_bearer_assertion(
    subject="alice@example.com",             # required — sub claim
    token_endpoint="https://…/token",        # required — used as aud claim
    issuer="https://your-tenant.verify.ibm.com",  # required — iss claim
    private_key="PEM_STRING",                # required — PEM-encoded RSA or EC private key
    algorithm="RS256",                       # optional (default: "RS256")
    expires_in=300,                          # optional — JWT lifetime in seconds (default: 300)
    audience=None,                           # optional — explicit aud override (defaults to token_endpoint)
    additional_claims=None,                  # optional — dict merged into the JWT payload
    key_id=None,                             # required — kid header identifying the signing certificate
)
# Returns: str — signed JWT for use as the assertion parameter in jwt_bearer_grant()
# Raises: ValueError — missing key_id, invalid key, or unsupported algorithm
```

---

## Exception Handling

All SDK errors raise `VerifyError`:

```python
from ibm_verify.oauth2.core.errors.errors import VerifyError

try:
    token = client.client_credentials(...)
except VerifyError as e:
    print(e.status_code)        # int | None — HTTP status code, when there was a response
    print(e.error)              # str | None — OAuth error code, e.g. "invalid_client"
    print(e.error_description)  # str | None — OAuth error_description
    print(e.dpop_nonce)         # str | None — DPoP-Nonce sent by the server, if any
    print(e.message)            # str — human-readable message
```

`VerifyError` is raised for:
- HTTP error responses from the token or API endpoint
- Network / connectivity failures (`httpx.RequestError`)
- OAuth protocol errors from Authlib

---

## SDK Modules

<details>
<summary>OAuth / OIDC layer</summary>

| Module | Description |
|---|---|
| `ibm_verify.oauth2.auth.client` | `OAuthClient` — single entry point composing all grant mixins |
| `ibm_verify.oauth2.grant_types.base` | `OAuthBase` — constructor params, HTTP client, endpoint resolution |
| `ibm_verify.oauth2.grant_types.constants` | Grant-type URNs and default endpoint paths |
| `ibm_verify.oauth2.grant_types.flows.discovery` | `DiscoveryMixin` — `load_discovery()`, `get_discovery()`, `get_jwks()` |
| `ibm_verify.oauth2.grant_types.flows.introspection` | `IntrospectMixin` — `introspect_token()` |
| `ibm_verify.oauth2.grant_types.flows.dpop` | `DPoPMixin` — `generate_dpop_key_pair()`, `generate_dpop_proof()`, `build_dpop_headers()`, `introspect_dpop_token()` |
| `ibm_verify.oauth2.grant_types.dpop` | Standalone DPoP helpers — `generate_dpop_proof()`, `verify_dpop_proof()`, `compute_jkt()`, `compute_ath()` |
| `ibm_verify.oauth2.grant_types.flows.registration` | `DcrMixin` — `register_client()`, `read_client()`, `update_client()`, `delete_client()` |
| `ibm_verify.oauth2.grant_types.utils` | `generate_pkce_pair()`, `generate_client_assertion_jwt()`, `generate_jwt_bearer_assertion()`, `build_authorization_url()` |
| `ibm_verify.oauth2.grant_types.grants.client_credentials` | `ClientCredentialsMixin` |
| `ibm_verify.oauth2.grant_types.grants.password` | `PasswordGrantMixin` |
| `ibm_verify.oauth2.grant_types.grants.authorization_code` | `AuthorizationCodeMixin` |
| `ibm_verify.oauth2.grant_types.grants.device_code` | `DeviceCodeMixin` |
| `ibm_verify.oauth2.grant_types.grants.token_exchange` | `TokenExchangeMixin` |
| `ibm_verify.oauth2.grant_types.grants.jwt_bearer` | `JWTBearerMixin` |
| `ibm_verify.oauth2.grant_types.grants.refresh_token` | `RefreshTokenMixin` |
| `ibm_verify.oauth2.core.errors.errors` | `VerifyError` base exception |

</details>

---

## Project Structure

```
verify-auth-python/
├── ibm_verify/
│   └── oauth2/
│       ├── auth/
│       │   └── client.py              # OAuthClient
│       ├── grant_types/
│       │   ├── base.py                # OAuthBase
│       │   ├── constants.py
│       │   ├── utils.py               # PKCE + JWT helpers
│       │   ├── dpop.py                # DPoP proof / thumbprint / verification helpers
│       │   ├── flows/                 # Protocol flows
│       │   │   ├── registration.py    # DcrMixin — Dynamic Client Registration
│       │   │   ├── discovery.py       # DiscoveryMixin
│       │   │   ├── dpop.py            # DPoPMixin
│       │   │   └── introspection.py   # IntrospectMixin
│       │   └── grants/                # Grant-type mixins
│       │       ├── authorization_code.py
│       │       ├── client_credentials.py
│       │       ├── device_code.py
│       │       ├── jwt_bearer.py
│       │       ├── password.py
│       │       ├── refresh_token.py
│       │       └── token_exchange.py
│       └── core/errors/errors.py      # VerifyError
│
├── test/
├── sample-scripts/
│   ├── .env.example                   # Credential template — copy to .env
│   └── *.py
├── certs/                             # Local dev certs (gitignored)
├── pyproject.toml
└── README.md
```

---

## Development

```bash
git clone https://github.com/ibm-verify/verify-auth-python.git
cd verify-auth-python

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,samples]"
```

Dev extras: `pytest`, `pytest-cov`, `pytest-asyncio`, `respx`, `black`, `ruff`, `mypy`.

Sample scripts depend on `python-dotenv`. Install sample dependencies with `pip install -e ".[samples]"` or include them during setup with `pip install -e ".[dev,samples]"`.

### Lint and format

```bash
ruff check ibm_verify/
ruff format ibm_verify/
```

### Run tests

```bash
pytest -v
```

---

## Contributing

You can contribute or open an issue to discuss significant changes before submitting a pull request.

- **`auth/` and `grant_types/`** — custom-built; direct PRs welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, coding conventions, commit format, and PR checklist.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full list of changes and known limitations.

---

## Support

- **Issues:** GitHub Issues - link to be added after the repository is public
- **IBM Verify docs:** [docs.verify.ibm.com](https://docs.verify.ibm.com/)

---

## License

[Apache License 2.0](LICENSE)