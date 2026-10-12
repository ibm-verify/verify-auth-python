# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — shared base class.

``OAuthBase`` holds the shared httpx.Client, connection settings, and all
endpoint-resolution logic.  Every grant module receives an instance of this
class, keeping configuration in one place.
"""

from typing import Any, Optional

import httpx
from authlib.oidc.discovery import OpenIDProviderMetadata

from ibm_verify.oauth2.grant_types.constants import (
    DEFAULT_AUTHORIZE_PATH,
    DEFAULT_DEVICE_AUTH_PATH,
    DEFAULT_INTROSPECT_PATH,
    DEFAULT_TOKEN_PATH,
)


class OAuthBase:
    """Shared configuration and endpoint resolution for all OAuth grant modules.

    Args:
        base_url: IBM Verify tenant URL (e.g. ``https://tenant.verify.ibm.com``).
        timeout: Request timeout in seconds (default: 30).
        verify_ssl: Verify SSL certificates (default: ``True``).
        token_endpoint: Explicit token endpoint — overrides discovery and default path.
        introspect_endpoint: Explicit introspection endpoint override.
        client_cert: Client certificate for mTLS. Path string or ``(cert, key)`` tuple.
        client_key: Client private-key path — only needed when ``client_cert`` is cert-only.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        verify_ssl: bool = True,
        token_endpoint: Optional[str] = None,
        introspect_endpoint: Optional[str] = None,
        client_cert: Optional[Any] = None,
        client_key: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self._explicit_token_endpoint = token_endpoint
        self._explicit_introspect_endpoint = introspect_endpoint

        self.client_cert = client_cert
        self.client_key = client_key

        # Populated by DiscoveryMixin.load_discovery()
        self._provider_metadata: Optional[OpenIDProviderMetadata] = None

        # Shared httpx.Client for unauthenticated calls (discovery, JWKS, device auth)
        self._http_client = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            cert=self._get_cert_param(),
        )

    # ── mTLS helper ──────────────────────────────────────────────────────────

    def _get_cert_param(self) -> Optional[Any]:
        """Return the ``cert`` kwarg for httpx: ``None``, a path string, or ``(cert, key)``."""
        if not self.client_cert:
            return None
        if self.client_key:
            return (self.client_cert, self.client_key)
        return self.client_cert

    # ── Endpoint resolvers ────────────────────────────────────────────────────

    def _resolve_token_endpoint(
        self,
        caller_endpoint: Optional[str] = None,
        op_name: str = "default",
    ) -> str:
        """Priority: caller override -> constructor override -> discovery -> default."""
        if caller_endpoint:
            return caller_endpoint
        if self._explicit_token_endpoint:
            return self._explicit_token_endpoint
        if self._provider_metadata:
            discovered = self._provider_metadata.get("token_endpoint")
            if discovered:
                return str(discovered)
        return f"{self.base_url}{DEFAULT_TOKEN_PATH}"

    def _resolve_introspect_endpoint(
        self,
        caller_endpoint: Optional[str] = None,
        op_name: str = "default",
    ) -> str:
        """Priority: caller override -> constructor override -> discovery -> default.

        Note: ``op_name`` is retained only for backward compatibility and is
        unused by the default path (``/oauth2/introspect``).
        """
        if caller_endpoint:
            return caller_endpoint
        if self._explicit_introspect_endpoint:
            return self._explicit_introspect_endpoint
        if self._provider_metadata:
            discovered = self._provider_metadata.get("introspection_endpoint")
            if discovered:
                return str(discovered)
        return f"{self.base_url}{DEFAULT_INTROSPECT_PATH}"

    def _resolve_authorize_endpoint(
        self,
        caller_endpoint: Optional[str] = None,
    ) -> str:
        """Priority: caller override -> discovery -> default."""
        if caller_endpoint:
            return caller_endpoint
        if self._provider_metadata:
            discovered = self._provider_metadata.get("authorization_endpoint")
            if discovered:
                return str(discovered)
        return f"{self.base_url}{DEFAULT_AUTHORIZE_PATH}"

    def _resolve_device_auth_endpoint(
        self,
        caller_endpoint: Optional[str] = None,
    ) -> str:
        """Priority: caller override -> discovery -> default."""
        if caller_endpoint:
            return caller_endpoint
        if self._provider_metadata:
            discovered = self._provider_metadata.get("device_authorization_endpoint")
            if discovered:
                return str(discovered)
        return f"{self.base_url}{DEFAULT_DEVICE_AUTH_PATH}"

    # ── Resource management ───────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying httpx.Client and release resources."""
        self._http_client.close()

    def __enter__(self) -> "OAuthBase":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
