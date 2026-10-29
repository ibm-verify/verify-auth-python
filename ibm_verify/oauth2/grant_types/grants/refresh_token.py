# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Refresh Token Grant (RFC 6749 §6).
"""

import json
from typing import Any, Callable, Optional, Union

from authlib.integrations.httpx_client import OAuth2Client

from ibm_verify.oauth2.grant_types.constants import CLIENT_ASSERTION_TYPE_JWT


class RefreshTokenMixin:
    """Mixin that adds the Refresh Token grant (RFC 6749 §6).

    Supports ``client_secret_post``, ``private_key_jwt``, and public clients.
    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def refresh_access_token(
        self,
        client_id: str,
        refresh_token: str,
        client_secret: Optional[str] = None,
        client_assertion: Optional[Union[str, Callable[[], str]]] = None,
        client_assertion_type: Optional[str] = None,
        scope: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
        dpop_private_key: Optional[str] = None,
        dpop_nonce: Optional[str] = None,
        dpop_algorithm: Optional[str] = None,
        client_secret_post: bool = False,
    ) -> dict[str, Any]:
        """Obtain a new access token from a refresh token (RFC 6749 §6).

        Supports ``client_secret_basic`` (default), ``client_secret_post``,
        ``private_key_jwt``, and public clients.

        Args:
            client_id: OAuth client ID.
            refresh_token: Refresh token from a previous token response.
            client_secret: Client secret (confidential clients, ``client_secret_post``).
            client_assertion: JWT for ``private_key_jwt`` client authentication.
                Generate with :func:`~ibm_verify.oauth2.grant_types.utils.generate_client_assertion_jwt`.
                Also accepts a zero-argument callable returning a fresh assertion
                (recommended with DPoP, so a nonce retry gets a new assertion).
            client_assertion_type: Assertion type URN (required with ``client_assertion``).
            scope: Optional scopes — must be a subset of the original grant.
            token_endpoint: Optional token endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.
            dpop_private_key: PEM private key. When set, a DPoP proof (RFC 9449) is sent
                in the ``DPoP`` header. Use the same key the refresh token is bound to.
            dpop_nonce: Server-provided ``DPoP-Nonce`` to embed in the proof. Usually not
                needed: a ``use_dpop_nonce`` challenge is retried automatically.
            dpop_algorithm: Proof JWS algorithm (default inferred from the key).
            client_secret_post: Send ``client_secret`` in the body instead of HTTP Basic.
                Required for IBM Verify applications that accept only
                ``client_secret_post`` (error CSIAQ0330E otherwise).

        Returns:
            Token response dict (``access_token``, ``refresh_token``, ``expires_in``, etc.).
        """
        endpoint = self._resolve_token_endpoint(token_endpoint)  # type: ignore[attr-defined]
        cert_param = self._get_cert_param()  # type: ignore[attr-defined]

        token_params: dict[str, Any] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if scope:
            token_params["scope"] = scope
        if authorization_details is not None:
            token_params["authorization_details"] = (
                json.dumps(authorization_details)
                if not isinstance(authorization_details, str)
                else authorization_details
            )
        if extra_params:
            token_params.update(extra_params)

        if client_assertion:
            oauth_client = OAuth2Client(
                client_id=client_id,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="none",
            )
            token_params["client_assertion"] = client_assertion
            token_params["client_assertion_type"] = (
                client_assertion_type or CLIENT_ASSERTION_TYPE_JWT
            )
        elif client_secret:
            oauth_client = OAuth2Client(
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method=(
                    "client_secret_post" if client_secret_post else "client_secret_basic"
                ),
            )
        else:
            # Public client / tls_client_auth via mTLS
            oauth_client = OAuth2Client(
                client_id=client_id,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="none",
            )
            token_params["client_id"] = client_id

        return self._fetch_token(  # type: ignore[attr-defined,no-any-return]
            oauth_client,
            endpoint,
            dpop_private_key=dpop_private_key,
            dpop_nonce=dpop_nonce,
            dpop_algorithm=dpop_algorithm,
            **token_params,
        )
