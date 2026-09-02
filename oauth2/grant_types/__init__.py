"""
IBM Verify OAuth package.

Provides a modular OAuth 2.0 / OIDC client for IBM Verify:

    oauth2/oauth/
    ├── constants.py               — URL paths and grant-type URNs
    ├── utils.py                   — PKCE helpers, JWT assertion builders
    ├── base.py                    — OAuthBase: shared httpx client + endpoint resolvers
    ├── flows/
    │   ├── discovery.py           — DiscoveryMixin: load_discovery, get_jwks
    │   ├── introspect.py          — IntrospectMixin: introspect_token
    │   └── dcr.py                 — DcrMixin: Dynamic Client Registration (RFC 7591/7592)
    └── grants/
        ├── password.py            — PasswordGrantMixin
        ├── client_credentials.py  — ClientCredentialsMixin
        ├── token_exchange.py      — TokenExchangeMixin
        ├── refresh_token.py       — RefreshTokenMixin
        ├── authorization_code.py  — AuthorizationCodeMixin
        ├── device_code.py         — DeviceCodeMixin
        └── jwt_bearer.py          — JWTBearerMixin

The top-level ``OAuthClient`` in ``oauth2.auth.client`` composes all
mixins and is the primary public API.  Individual mixins and utilities can
also be imported directly from this package for advanced use-cases.
"""

from oauth2.grant_types.base import OAuthBase
from oauth2.grant_types.constants import (
    CLIENT_ASSERTION_TYPE_JWT,
    DEFAULT_AUTHORIZE_PATH,
    DEFAULT_DEVICE_AUTH_PATH,
    DEFAULT_INTROSPECT_PATH,
    DEFAULT_REGISTRATION_PATH,
    DEFAULT_TOKEN_PATH,
    GRANT_AUTHORIZATION_CODE,
    GRANT_CLIENT_CREDENTIALS,
    GRANT_DEVICE_CODE,
    GRANT_JWT_BEARER,
    GRANT_PASSWORD,
    GRANT_REFRESH_TOKEN,
    GRANT_TOKEN_EXCHANGE,
    JWT_BEARER_ASSERTION_EXPIRES_IN,
    JWT_CLIENT_ASSERTION_EXPIRES_IN,
    JWT_DEFAULT_ALGORITHM,
    PKCE_CHALLENGE_METHOD,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_ID_TOKEN,
    TOKEN_TYPE_JWT,
    TOKEN_TYPE_REFRESH_TOKEN,
)
from oauth2.grant_types.flows.registration import DcrMixin
from oauth2.grant_types.flows.discovery import DiscoveryMixin
from oauth2.grant_types.grants.authorization_code import AuthorizationCodeMixin
from oauth2.grant_types.grants.client_credentials import ClientCredentialsMixin
from oauth2.grant_types.grants.device_code import DeviceCodeMixin
from oauth2.grant_types.grants.jwt_bearer import JWTBearerMixin
from oauth2.grant_types.grants.password import PasswordGrantMixin
from oauth2.grant_types.grants.refresh_token import RefreshTokenMixin
from oauth2.grant_types.grants.token_exchange import TokenExchangeMixin
from oauth2.grant_types.flows.introspection import IntrospectMixin
from oauth2.grant_types.utils import (
    build_authorization_url,
    generate_client_assertion_jwt,
    generate_jwt_bearer_assertion,
    generate_pkce_pair,
)

__all__ = [
    # Base
    "OAuthBase",
    # Mixins
    "DcrMixin",
    "DiscoveryMixin",
    "IntrospectMixin",
    "PasswordGrantMixin",
    "ClientCredentialsMixin",
    "TokenExchangeMixin",
    "RefreshTokenMixin",
    "AuthorizationCodeMixin",
    "DeviceCodeMixin",
    "JWTBearerMixin",
    # Utilities
    "generate_pkce_pair",
    "build_authorization_url",
    "generate_client_assertion_jwt",
    "generate_jwt_bearer_assertion",
    # Constants
    "DEFAULT_TOKEN_PATH",
    "DEFAULT_INTROSPECT_PATH",
    "DEFAULT_AUTHORIZE_PATH",
    "DEFAULT_DEVICE_AUTH_PATH",
    "GRANT_PASSWORD",
    "GRANT_CLIENT_CREDENTIALS",
    "GRANT_AUTHORIZATION_CODE",
    "GRANT_REFRESH_TOKEN",
    "GRANT_DEVICE_CODE",
    "GRANT_TOKEN_EXCHANGE",
    "GRANT_JWT_BEARER",
    "CLIENT_ASSERTION_TYPE_JWT",
    "TOKEN_TYPE_ACCESS_TOKEN",
    "TOKEN_TYPE_REFRESH_TOKEN",
    "TOKEN_TYPE_ID_TOKEN",
    "TOKEN_TYPE_JWT",
    "DEFAULT_REGISTRATION_PATH",
    "PKCE_CHALLENGE_METHOD",
    "JWT_DEFAULT_ALGORITHM",
    "JWT_CLIENT_ASSERTION_EXPIRES_IN",
    "JWT_BEARER_ASSERTION_EXPIRES_IN",
]
