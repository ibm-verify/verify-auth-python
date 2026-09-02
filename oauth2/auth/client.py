"""
IBM Verify OAuth client.

``OAuthClient`` is the single public entry point for all token-acquisition
and OAuth 2.0 operations.  It composes every mixin into one coherent class::

    from oauth2.auth.client import OAuthClient

    client = OAuthClient(base_url="https://your-tenant.verify.ibm.com")
    client.load_discovery()
    token = client.client_credentials(client_id="...", client_secret="...")
"""

from oauth2.grant_types.base import OAuthBase
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

        from oauth2.auth.client import OAuthClient

        with OAuthClient(base_url="https://your-tenant.verify.ibm.com") as client:
            client.load_discovery()
            token = client.client_credentials(
                client_id="my-app",
                client_secret="s3cr3t",
            )
    """
