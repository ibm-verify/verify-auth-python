# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — shared constants.

All URL default paths and grant-type URNs live here so they never
need to be duplicated across grant modules.
"""

# ── Default IBM Verify endpoint paths ─────────────────────────────────────────
DEFAULT_TOKEN_PATH = "/oauth2/token"
DEFAULT_INTROSPECT_PATH = "/oauth2/introspect"
DEFAULT_AUTHORIZE_PATH = "/oauth2/authorize"
DEFAULT_DEVICE_AUTH_PATH = "/oauth2/device_authorization"
DEFAULT_REGISTRATION_PATH = "/oauth2/register"

# ── OAuth 2.0 grant type URNs ─────────────────────────────────────────────────
GRANT_PASSWORD = "password"
GRANT_CLIENT_CREDENTIALS = "client_credentials"
GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_REFRESH_TOKEN = "refresh_token"
GRANT_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# ── Client assertion type ─────────────────────────────────────────────────────
CLIENT_ASSERTION_TYPE_JWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# ── Token type URNs — Token Exchange (RFC 8693) ───────────────────────────────
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

# ── PKCE ──────────────────────────────────────────────────────────────────────
PKCE_CHALLENGE_METHOD = "S256"
PKCE_VERIFIER_BYTE_LENGTH = 96   # 96 bytes → 128-char URL-safe base64 string

# ── JWT defaults ──────────────────────────────────────────────────────────────
JWT_DEFAULT_ALGORITHM = "RS256"
JWT_CLIENT_ASSERTION_EXPIRES_IN = 300   # 5 minutes
JWT_BEARER_ASSERTION_EXPIRES_IN = 300   # 5 minutes
