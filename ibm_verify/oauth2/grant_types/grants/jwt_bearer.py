# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — JWT Bearer Grant (RFC 7523).
"""

import json
from typing import Any, Callable, Optional, Union

from authlib.integrations.httpx_client import OAuth2Client

from ibm_verify.oauth2.grant_types.constants import CLIENT_ASSERTION_TYPE_JWT, GRANT_JWT_BEARER
from ibm_verify.oauth2.grant_types.utils import (
    generate_client_assertion_jwt,
    generate_jwt_bearer_assertion,
)


class JWTBearerMixin:
    """Mixin that adds the JWT Bearer grant and its assertion helpers (RFC 7523).

    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    # Re-expose the pure utility functions as static methods so callers can
    # use either ``OAuthClient.generate_jwt_bearer_assertion(...)`` or the
    # standalone import from ``ibm_verify.oauth2.grant_types.utils``.
    generate_client_assertion_jwt = staticmethod(generate_client_assertion_jwt)
    generate_jwt_bearer_assertion = staticmethod(generate_jwt_bearer_assertion)

    def jwt_bearer_grant(
        self,
        assertion: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        client_assertion: Optional[Union[str, Callable[[], str]]] = None,
        client_assertion_type: str = CLIENT_ASSERTION_TYPE_JWT,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
        dpop_private_key: Optional[str] = None,
        dpop_nonce: Optional[str] = None,
        dpop_algorithm: Optional[str] = None,
    ) -> dict[str, Any]:
        """Exchange a JWT assertion for an access token (RFC 7523 jwt-bearer grant).

        Supports multiple client authentication methods:

        - ``client_secret_post``: provide ``client_id`` + ``client_secret``
        - ``private_key_jwt``: provide ``client_id`` + ``client_assertion``
        - none / public: provide only ``client_id`` (or omit it)

        Args:
            assertion: Signed JWT assertion.
                Generate with :func:`~ibm_verify.oauth2.grant_types.utils.generate_jwt_bearer_assertion`.
            client_id: OAuth client ID.
            client_secret: Client secret for ``client_secret_post`` clients.
            scope: Optional requested scopes (space-separated).
            token_endpoint: Optional explicit token endpoint URL.
            client_assertion: Signed JWT for ``private_key_jwt`` client authentication.
                Also accepts a zero-argument callable returning a fresh assertion
                (recommended with DPoP, so a nonce retry gets a new assertion).
            client_assertion_type: Assertion type URN for client auth JWT.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.
            dpop_private_key: PEM private key. When set, a DPoP proof (RFC 9449) is sent
                in the ``DPoP`` header and a DPoP-bound token is requested.
            dpop_nonce: Server-provided ``DPoP-Nonce`` (normally handled automatically).
            dpop_algorithm: Proof JWS algorithm (default inferred from the key).

        Returns:
            Token response dict (``access_token``, ``token_type``, ``expires_in``, etc.).
        """
        endpoint = self._resolve_token_endpoint(token_endpoint)  # type: ignore[attr-defined]
        cert_param = self._get_cert_param()  # type: ignore[attr-defined]

        body: dict[str, Any] = {
            "grant_type": GRANT_JWT_BEARER,
            "assertion": assertion,
        }
        if scope:
            body["scope"] = scope
        if client_assertion:
            body["client_assertion"] = client_assertion
            body["client_assertion_type"] = client_assertion_type
        if authorization_details is not None:
            body["authorization_details"] = (
                json.dumps(authorization_details)
                if not isinstance(authorization_details, str)
                else authorization_details
            )
        if extra_params:
            body.update(extra_params)

        if client_id and client_assertion:
            oauth_client = OAuth2Client(
                client_id=client_id,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="none",
            )
            body["client_id"] = client_id
        elif client_id and client_secret:
            oauth_client = OAuth2Client(
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="client_secret_post",
            )
        elif client_id:
            oauth_client = OAuth2Client(
                client_id=client_id,
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="none",
            )
            body["client_id"] = client_id
        else:
            oauth_client = OAuth2Client(
                token_endpoint=endpoint,
                timeout=self.timeout,  # type: ignore[attr-defined]
                verify=self.verify_ssl,  # type: ignore[attr-defined]
                cert=cert_param,
                token_endpoint_auth_method="none",
            )

        return self._fetch_token(  # type: ignore[attr-defined,no-any-return]
            oauth_client,
            endpoint,
            dpop_private_key=dpop_private_key,
            dpop_nonce=dpop_nonce,
            dpop_algorithm=dpop_algorithm,
            **body,
        )
