# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
IBM Verify OAuth client.

``OAuthClient`` is the single public entry point for all token-acquisition
and OAuth 2.0 operations.  It composes every mixin into one coherent class::

    from ibm_verify.auth.client import OAuthClient

    client = OAuthClient(base_url="https://your-tenant.verify.ibm.com")
    client.load_discovery()
    token = client.client_credentials(client_id="...", client_secret="...")
"""

from ibm_verify.oauth.base import OAuthBase
from ibm_verify.oauth.flows.dcr import DcrMixin
from ibm_verify.oauth.flows.discovery import DiscoveryMixin
from ibm_verify.oauth.grants.authorization_code import AuthorizationCodeMixin
from ibm_verify.oauth.grants.client_credentials import ClientCredentialsMixin
from ibm_verify.oauth.grants.device_code import DeviceCodeMixin
from ibm_verify.oauth.grants.jwt_bearer import JWTBearerMixin
from ibm_verify.oauth.grants.password import PasswordGrantMixin
from ibm_verify.oauth.grants.refresh_token import RefreshTokenMixin
from ibm_verify.oauth.grants.token_exchange import TokenExchangeMixin
from ibm_verify.oauth.flows.introspect import IntrospectMixin


class OAuthClient(
    DiscoveryMixin,
    IntrospectMixin,
    PasswordGrantMixin,
    ClientCredentialsMixin,
    TokenExchangeMixin,
    RefreshTokenMixin,
    AuthorizationCodeMixin,
    DeviceCodeMixin,
    JWTBearerMixin,
    DcrMixin,
    OAuthBase,
):
    """Single entry point for all OAuth 2.0 / OIDC token operations.

    Args:
        base_url: IBM Verify tenant URL (e.g. ``https://tenant.verify.ibm.com``).
        timeout: Request timeout in seconds (default: 30).
        verify_ssl: Verify SSL certificates (default: ``True``).
        token_endpoint: Explicit token endpoint — overrides discovery and default path.
        introspect_endpoint: Explicit introspection endpoint override.
        client_cert: Client certificate for mTLS. Path string or ``(cert, key)`` tuple.
        client_key: Client private-key path — only needed when ``client_cert`` is cert-only.

    Example::

        from ibm_verify.auth.client import OAuthClient

        with OAuthClient(base_url="https://your-tenant.verify.ibm.com") as client:
            client.load_discovery()
            token = client.client_credentials(
                client_id="my-app",
                client_secret="s3cr3t",
            )
    """
