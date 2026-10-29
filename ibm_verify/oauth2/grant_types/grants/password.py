# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Password Grant (RFC 6749 §4.3).

Resource Owner Password Credentials grant.
"""

import json
from typing import Any, Optional

from authlib.integrations.httpx_client import OAuth2Client

from ibm_verify.oauth2.grant_types.base import _keep_request_auth


class PasswordGrantMixin:
    """Mixin that adds the Resource Owner Password Credentials grant.

    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def password_grant(
        self,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        authorization_header: str,
        scope: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
        dpop_private_key: Optional[str] = None,
        dpop_nonce: Optional[str] = None,
        dpop_algorithm: Optional[str] = None,
    ) -> dict[str, Any]:
        """Exchange username/password for tokens (RFC 6749 §4.3).

        Args:
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            username: Resource owner username.
            password: Resource owner password.
            authorization_header: Pre-encoded ``Authorization`` header, used only when
                ``client_secret`` is empty. Otherwise the SDK sends ``client_id`` /
                ``client_secret`` with HTTP Basic auth.
            scope: Optional space-separated scope string.
            token_endpoint: Optional token endpoint override.
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

        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=endpoint,
            timeout=self.timeout,  # type: ignore[attr-defined]
            verify=self.verify_ssl,  # type: ignore[attr-defined]
            cert=self._get_cert_param(),  # type: ignore[attr-defined]
        )
        fetch_kwargs: dict[str, Any] = {
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        use_header = bool(authorization_header) and not client_secret
        if use_header:
            # No secret: send the caller's pre-built header as given.
            fetch_kwargs["auth"] = _keep_request_auth
            fetch_kwargs["client_id"] = client_id
        if scope:
            fetch_kwargs["scope"] = scope
        if authorization_details is not None:
            fetch_kwargs["authorization_details"] = (
                json.dumps(authorization_details)
                if not isinstance(authorization_details, str)
                else authorization_details
            )
        if extra_params:
            fetch_kwargs.update(extra_params)
        return self._fetch_token(  # type: ignore[attr-defined,no-any-return]
            client,
            endpoint,
            headers={"Authorization": authorization_header} if use_header else None,
            dpop_private_key=dpop_private_key,
            dpop_nonce=dpop_nonce,
            dpop_algorithm=dpop_algorithm,
            **fetch_kwargs,
        )
