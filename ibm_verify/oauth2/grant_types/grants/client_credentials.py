# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Client Credentials Grant (RFC 6749 §4.4).
"""

import json
from typing import Any, Callable, Optional, Union

from authlib.integrations.httpx_client import OAuth2Client

from ibm_verify.oauth2.grant_types.base import _keep_request_auth
from ibm_verify.oauth2.grant_types.constants import CLIENT_ASSERTION_TYPE_JWT


class ClientCredentialsMixin:
    """Mixin that adds the Client Credentials grant.

    Supports ``client_secret_basic`` (via ``authorization_header`` or the default),
    ``client_secret_post`` and ``private_key_jwt``.
    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def client_credentials(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
        authorization_header: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
        dpop_private_key: Optional[str] = None,
        dpop_nonce: Optional[str] = None,
        dpop_algorithm: Optional[str] = None,
        client_assertion: Optional[Union[str, Callable[[], str]]] = None,
        client_assertion_type: Optional[str] = None,
        client_secret_post: bool = False,
    ) -> dict[str, Any]:
        """Obtain an access token using client identity only (RFC 6749 §4.4).

        Client authentication (first match wins):

        - ``client_assertion`` → ``private_key_jwt`` (``client_id``, ``client_assertion``
          and ``client_assertion_type`` in the body). Build the assertion with
          :func:`~ibm_verify.oauth2.grant_types.utils.generate_client_assertion_jwt`.
        - ``client_secret`` with ``client_secret_post=True`` → secret in the body.
        - ``client_secret`` → ``client_secret_basic`` (built by the SDK; any
          ``authorization_header`` is ignored).
        - ``authorization_header`` alone → sent as given (e.g. a pre-encoded
          ``Basic …``), with ``client_id`` in the body.

        Args:
            client_id: OAuth client ID.
            client_secret: OAuth client secret (not needed for ``private_key_jwt``).
            scope: Space-separated OAuth scopes.
            authorization_header: Pre-encoded ``Authorization`` header, used only when no
                ``client_secret`` or ``client_assertion`` is given.
            token_endpoint: Optional token endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.
            dpop_private_key: PEM private key. When set, a DPoP proof (RFC 9449) is sent
                in the ``DPoP`` header and a DPoP-bound token is requested.
            dpop_nonce: Server-provided ``DPoP-Nonce`` to embed in the proof. Usually not
                needed: a ``use_dpop_nonce`` challenge is retried automatically.
            dpop_algorithm: Proof JWS algorithm (default inferred from the key); must match
                the application's "Signing algorithm for DPoP JWT".
            client_assertion: Signed JWT for ``private_key_jwt`` client authentication.
                Also accepts a zero-argument callable returning a fresh assertion
                (recommended with DPoP, so a nonce retry gets a new assertion).
            client_assertion_type: Assertion type URN (default: jwt-bearer).
            client_secret_post: Send ``client_secret`` in the body instead of Basic auth.

        Returns:
            Token response dict (``access_token``, ``token_type``, ``expires_in``, etc.).

        Raises:
            ValueError: If no client authentication was supplied.
            VerifyError: If the token request fails.
        """
        if not (client_assertion or authorization_header or client_secret):
            raise ValueError(
                "client_credentials requires client_secret, authorization_header "
                "or client_assertion"
            )
        endpoint = self._resolve_token_endpoint(token_endpoint)  # type: ignore[attr-defined]
        cert_param = self._get_cert_param()  # type: ignore[attr-defined]

        params: dict[str, Any] = {"grant_type": "client_credentials"}
        if scope:
            params["scope"] = scope
        if authorization_details is not None:
            params["authorization_details"] = (
                json.dumps(authorization_details)
                if not isinstance(authorization_details, str)
                else authorization_details
            )

        headers: Optional[dict[str, str]] = None
        if client_assertion:
            oauth_client = OAuth2Client(
                client_id=client_id,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="none",
            )
            params["client_id"] = client_id
            params["client_assertion"] = client_assertion
            params["client_assertion_type"] = client_assertion_type or CLIENT_ASSERTION_TYPE_JWT
        elif client_secret:
            # The SDK builds the client credentials itself; a caller-supplied
            # authorization_header is not used when the secret is known.
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
            # Only a pre-built Authorization header: send it as given.
            oauth_client = OAuth2Client(
                client_id=client_id,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="none",
            )
            headers = {"Authorization": str(authorization_header)}
            params["auth"] = _keep_request_auth
            params["client_id"] = client_id

        if extra_params:
            params.update(extra_params)

        return self._fetch_token(  # type: ignore[attr-defined,no-any-return]
            oauth_client,
            endpoint,
            headers=headers,
            dpop_private_key=dpop_private_key,
            dpop_nonce=dpop_nonce,
            dpop_algorithm=dpop_algorithm,
            **params,
        )
