# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Client Credentials Grant (RFC 6749 §4.4).
"""

import json
from typing import Any, Optional

import httpx
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.httpx_client import OAuth2Client

from ibm_verify.oauth2.core.errors.errors import VerifyError


class ClientCredentialsMixin:
    """Mixin that adds the Client Credentials grant.

    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def client_credentials(
        self,
        client_id: str,
        client_secret: str,
        scope: str,
        authorization_header: str,
        token_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Obtain an access token using client identity only (RFC 6749 §4.4).

        Args:
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            scope: Space-separated OAuth scopes.
            authorization_header: ``Authorization`` header value.
            token_endpoint: Optional token endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.

        Returns:
            Token response dict (``access_token``, ``token_type``, ``expires_in``, etc.).
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
        )
        try:
            token = client.fetch_token(
                url=endpoint,
                grant_type="client_credentials",
                scope=scope,
                headers={"Authorization": authorization_header},
                **extra,
            )
        except AuthlibBaseError as exc:
            raise VerifyError(
                message=str(exc),
                error=exc.error,
                error_description=exc.description or "",
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise VerifyError(
                message=str(exc),
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=str(exc)) from exc
        return dict(token)
