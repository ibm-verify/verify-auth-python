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
from authlib.common.errors import AuthlibBaseError
from authlib.oidc.discovery import OpenIDProviderMetadata

from ibm_verify.oauth2.core.errors.errors import VerifyError
from ibm_verify.oauth2.grant_types.constants import (
    DEFAULT_AUTHORIZE_PATH,
    DEFAULT_DEVICE_AUTH_PATH,
    DEFAULT_INTROSPECT_PATH,
    DEFAULT_TOKEN_PATH,
)
from ibm_verify.oauth2.grant_types.dpop import (
    build_token_request_dpop_header,
    dpop_origin,
    warn_if_not_dpop_token,
)


def _keep_request_auth(request: httpx.Request) -> httpx.Request:
    """httpx auth callable that leaves a caller-supplied ``Authorization`` header intact."""
    return request


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

        # Most recent DPoP-Nonce seen per server origin (RFC 9449 §8 / §9).
        self._dpop_nonces: dict[str, str] = {}

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

    # ── DPoP nonce cache ──────────────────────────────────────────────────────

    def get_dpop_nonce(self, url: str) -> Optional[str]:
        """Return the last ``DPoP-Nonce`` the server at ``url``'s origin provided, if any."""
        return self._dpop_nonces.get(dpop_origin(url))

    def _remember_dpop_nonce(self, url: str, headers: Any) -> Optional[str]:
        nonce = headers.get("dpop-nonce") if headers is not None else None
        if nonce:
            self._dpop_nonces[dpop_origin(url)] = nonce
        return str(nonce) if nonce else None

    # ── Token endpoint request (shared by all grant mixins) ──────────────────

    def _fetch_token(
        self,
        oauth_client: Any,
        endpoint: str,
        headers: Optional[dict[str, str]] = None,
        dpop_private_key: Optional[str] = None,
        dpop_nonce: Optional[str] = None,
        dpop_algorithm: Optional[str] = None,
        **params: Any,
    ) -> dict[str, Any]:
        """POST to the token endpoint through ``oauth_client`` and return the token.

        When ``dpop_private_key`` is set a fresh DPoP proof is attached.  The
        nonce used is ``dpop_nonce`` or, if not given, the last ``DPoP-Nonce``
        this server sent.  If the server answers ``use_dpop_nonce`` the request
        is retried once with the nonce it supplied (RFC 9449 §8).  If
        ``params["client_assertion"]`` is a callable it is called for every attempt,
        so the retry carries a fresh ``private_key_jwt`` assertion.  Errors are
        raised as :class:`VerifyError` (with ``dpop_nonce`` populated when the
        server sent one).  ``oauth_client`` is closed afterwards.
        """
        last_headers: dict[str, Any] = {}

        def _capture(response: httpx.Response) -> None:
            last_headers["value"] = response.headers
            last_headers["status"] = response.status_code
            self._remember_dpop_nonce(endpoint, response.headers)

        hooks = dict(oauth_client.event_hooks)
        hooks["response"] = [*hooks.get("response", []), _capture]
        oauth_client.event_hooks = hooks

        nonce = dpop_nonce or (self.get_dpop_nonce(endpoint) if dpop_private_key else None)
        attempts = 2 if dpop_private_key else 1
        try:
            for attempt in range(attempts):
                request_headers = dict(headers) if headers else None
                if dpop_private_key:
                    request_headers = request_headers or {}
                    request_headers.update(
                        build_token_request_dpop_header(
                            dpop_private_key, endpoint, nonce=nonce, algorithm=dpop_algorithm
                        )
                    )
                # A callable client_assertion is invoked per attempt so a nonce retry
                # sends a fresh assertion (servers may reject a reused assertion jti).
                attempt_params = dict(params)
                if callable(attempt_params.get("client_assertion")):
                    attempt_params["client_assertion"] = attempt_params["client_assertion"]()
                try:
                    token = oauth_client.fetch_token(
                        url=endpoint, headers=request_headers, **attempt_params
                    )
                    break
                except AuthlibBaseError as exc:
                    server_nonce = (last_headers.get("value") or {}).get("dpop-nonce")
                    if (
                        dpop_private_key
                        and exc.error == "use_dpop_nonce"
                        and server_nonce
                        and server_nonce != nonce
                        and attempt + 1 < attempts
                    ):
                        nonce = server_nonce
                        continue
                    raise VerifyError(
                        message=str(exc),
                        status_code=last_headers.get("status"),
                        error=exc.error,
                        error_description=exc.description or "",
                        dpop_nonce=server_nonce,
                    ) from exc
                except httpx.HTTPStatusError as exc:
                    raise VerifyError(
                        message=str(exc),
                        status_code=exc.response.status_code,
                        dpop_nonce=exc.response.headers.get("dpop-nonce"),
                    ) from exc
                except httpx.RequestError as exc:
                    raise VerifyError(message=str(exc)) from exc
                except ValueError as exc:  # non-JSON token response
                    raise VerifyError(
                        message=f"Invalid token endpoint response: {exc}",
                        status_code=last_headers.get("status"),
                    ) from exc
        finally:
            oauth_client.close()

        if dpop_private_key:
            warn_if_not_dpop_token(token)
        return dict(token)

    # ── Resource management ───────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying httpx.Client and release resources."""
        self._http_client.close()

    def __enter__(self) -> "OAuthBase":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
