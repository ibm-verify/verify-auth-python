# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Token Exchange Grant (RFC 8693).
"""

import json
from typing import Any, Optional

from authlib.integrations.httpx_client import OAuth2Client

from ibm_verify.oauth2.grant_types.constants import (
    GRANT_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
)


class TokenExchangeMixin:
    """Mixin that adds the Token Exchange grant (RFC 8693).

    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def token_exchange(
        self,
        client_id: str,
        client_secret: str,
        subject_token: str,
        actor_token: str,
        token_endpoint: Optional[str] = None,
        subject_token_type: str = TOKEN_TYPE_ACCESS_TOKEN,
        actor_token_type: str = TOKEN_TYPE_ACCESS_TOKEN,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
        dpop_private_key: Optional[str] = None,
        dpop_nonce: Optional[str] = None,
        dpop_algorithm: Optional[str] = None,
    ) -> dict[str, Any]:
        """Exchange one set of tokens for another (RFC 8693).

        Args:
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            subject_token: Token representing the subject (being exchanged).
            actor_token: Token representing the acting party (delegation).
            token_endpoint: Optional token endpoint override.
            subject_token_type: URN for the subject token type.
            actor_token_type: URN for the actor token type.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.
            dpop_private_key: PEM private key. When set, a DPoP proof (RFC 9449) is sent
                in the ``DPoP`` header and a DPoP-bound token is requested.
            dpop_nonce: Server-provided ``DPoP-Nonce`` (normally handled automatically).
            dpop_algorithm: Proof JWS algorithm (default inferred from the key).

        Returns:
            Token response dict with the exchanged ``access_token``.
        """
        endpoint = self._resolve_token_endpoint(token_endpoint)  # type: ignore[attr-defined]

        extra: dict[str, Any] = {}
        if authorization_details is not None:
            extra["authorization_details"] = (
                json.dumps(authorization_details)
                if not isinstance(authorization_details, str)
                else authorization_details
            )
        if extra_params:
            extra.update(extra_params)

        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=endpoint,
            timeout=self.timeout,  # type: ignore[attr-defined]
            verify=self.verify_ssl,  # type: ignore[attr-defined]
            cert=self._get_cert_param(),  # type: ignore[attr-defined]
        )
        return self._fetch_token(  # type: ignore[attr-defined,no-any-return]
            client,
            endpoint,
            dpop_private_key=dpop_private_key,
            dpop_nonce=dpop_nonce,
            dpop_algorithm=dpop_algorithm,
            grant_type=GRANT_TOKEN_EXCHANGE,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            **extra,
        )
