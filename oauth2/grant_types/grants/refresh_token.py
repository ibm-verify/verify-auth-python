"""
IBM Verify OAuth — Refresh Token Grant (RFC 6749 §6).
"""

import json
from typing import Any, Dict, Optional

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from authlib.common.errors import AuthlibBaseError

from oauth2.core.errors.errors import VerifyError

from oauth2.grant_types.constants import CLIENT_ASSERTION_TYPE_JWT


class RefreshTokenMixin:
    """Mixin that adds the Refresh Token grant (RFC 6749 §6).

    Supports ``client_secret_post``, ``private_key_jwt``, and public clients.
    Requires :class:`~oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def refresh_access_token(
        self,
        client_id: str,
        refresh_token: str,
        client_secret: Optional[str] = None,
        client_assertion: Optional[str] = None,
        client_assertion_type: Optional[str] = None,
        scope: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Obtain a new access token from a refresh token (RFC 6749 §6).

        Supports ``client_secret_post``, ``private_key_jwt``, and public clients.

        Args:
            client_id: OAuth client ID.
            refresh_token: Refresh token from a previous token response.
            client_secret: Client secret (confidential clients, ``client_secret_post``).
            client_assertion: JWT for ``private_key_jwt`` client authentication.
                Generate with :func:`~oauth2.grant_types.utils.generate_client_assertion_jwt`.
            client_assertion_type: Assertion type URN (required with ``client_assertion``).
            scope: Optional scopes — must be a subset of the original grant.
            token_endpoint: Optional token endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.

        Returns:
            Token response dict (``access_token``, ``refresh_token``, ``expires_in``, etc.).
        """
        endpoint = self._resolve_token_endpoint(token_endpoint)  # type: ignore[attr-defined]
        cert_param = self._get_cert_param()  # type: ignore[attr-defined]

        token_params: Dict[str, Any] = {
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

        try:
            token = oauth_client.fetch_token(url=endpoint, **token_params)
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
