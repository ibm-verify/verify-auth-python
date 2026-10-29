# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — OIDC Discovery and JWKS.

Provides ``DiscoveryMixin`` which is composed into ``OAuthClient``.
"""

from typing import Any, Optional

import httpx
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url

from ibm_verify.oauth2.core.errors.errors import VerifyError


class DiscoveryMixin:
    """Mixin that adds OIDC discovery document loading and JWKS fetching.

    Requires ``self.base_url``, ``self._http_client``, and
    ``self._provider_metadata`` from :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase`.
    """

    def load_discovery(
        self,
        op_name: str = "default",
        discovery_url: Optional[str] = None,
    ) -> OpenIDProviderMetadata:
        """Fetch and cache the OIDC discovery document.

        Args:
            op_name: OIDC provider name (default: ``"default"``).
            discovery_url: Explicit discovery URL override.

        Returns:
            ``OpenIDProviderMetadata`` populated with endpoint URLs.
        """
        if discovery_url:
            url = discovery_url
        else:
            issuer = f"{self.base_url}/oauth2"  # type: ignore[attr-defined]
            url = get_well_known_url(issuer, external=True)

        try:
            response = self._http_client.get(url)  # type: ignore[attr-defined]
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VerifyError(
                message=f"Discovery request failed: {exc}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=f"Discovery request failed: {exc}") from exc

        self._provider_metadata = OpenIDProviderMetadata(response.json())
        return self._provider_metadata

    def get_discovery(
        self,
        op_name: str = "default",
        discovery_url: Optional[str] = None,
    ) -> OpenIDProviderMetadata:
        """Return cached discovery metadata, fetching if not yet loaded.

        Args:
            op_name: OIDC provider name (default: ``"default"``).
            discovery_url: Explicit discovery URL override.

        Returns:
            Cached ``OpenIDProviderMetadata`` instance.
        """
        if self._provider_metadata is None:
            self.load_discovery(op_name=op_name, discovery_url=discovery_url)
        return self._provider_metadata

    def get_jwks(
        self,
        op_name: str = "default",
        jwks_uri: Optional[str] = None,
    ) -> dict[str, Any]:
        """Fetch the JSON Web Key Set (JWKS).

        Args:
            op_name: OIDC provider name (default: ``"default"``).
            jwks_uri: Explicit JWKS URI override.

        Returns:
            JWKS document dict.
        """
        if jwks_uri:
            uri = jwks_uri
        else:
            metadata = self.get_discovery(op_name=op_name)
            uri = metadata.get("jwks_uri")
            if not uri:
                raise ValueError("jwks_uri not found in discovery document.")

        try:
            response = self._http_client.get(str(uri))  # type: ignore[attr-defined]
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VerifyError(
                message=f"JWKS request failed: {exc}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=f"JWKS request failed: {exc}") from exc
        return dict(response.json())
