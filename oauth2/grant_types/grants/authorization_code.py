# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Authorization Code + PKCE Grant (RFC 7636).
"""

import json
from typing import Any, Optional

import httpx
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.httpx_client import OAuth2Client

from oauth2.core.errors.errors import VerifyError
from oauth2.grant_types.constants import CLIENT_ASSERTION_TYPE_JWT
from oauth2.grant_types.utils import build_authorization_url, generate_pkce_pair


class AuthorizationCodeMixin:
    """Mixin that adds Authorization Code + PKCE (RFC 7636).

    Supports ``client_secret_post``, ``private_key_jwt``, and public clients.
    Requires :class:`~oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    @staticmethod
    def generate_pkce_pair():
        """Generate a PKCE ``(code_verifier, code_challenge)`` pair using S256.

        Returns:
            ``(code_verifier, code_challenge)`` tuple of URL-safe base64 strings.
        """
        return generate_pkce_pair()

    def build_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        scope: str = "openid profile email",
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        authorize_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
    ) -> str:
        """Build the Authorization Code + PKCE redirect URL (RFC 7636).

        Args:
            client_id: OAuth client ID.
            redirect_uri: Redirect URI registered with IBM Verify.
            code_challenge: S256 code challenge from :meth:`generate_pkce_pair`.
            scope: Space-separated scopes (default: ``"openid profile email"``).
            state: CSRF state — auto-generated if omitted.
            nonce: Optional nonce for ID-token replay protection.
            authorize_endpoint: Optional authorization endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the query parameter.
            extra_params: Additional query parameters to include in the URL.

        Returns:
            Authorization URL to redirect the user's browser to.
        """
        endpoint = self._resolve_authorize_endpoint(authorize_endpoint)  # type: ignore[attr-defined]
        return build_authorization_url(
            authorize_endpoint=endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            scope=scope,
            state=state,
            nonce=nonce,
            authorization_details=authorization_details,
            extra_params=extra_params,
        )

    def exchange_code_for_token(
        self,
        client_id: str,
        redirect_uri: str,
        code: str,
        code_verifier: str,
        client_secret: Optional[str] = None,
        client_assertion: Optional[str] = None,
        client_assertion_type: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Exchange an authorization code for tokens — Step 2 of PKCE flow (RFC 7636).

        Supports ``client_secret_post``, ``private_key_jwt``, and public clients.

        Args:
            client_id: OAuth client ID.
            redirect_uri: Must exactly match the URI used in :meth:`build_authorization_url`.
            code: Authorization code from the redirect callback.
            code_verifier: PKCE verifier from :meth:`generate_pkce_pair`.
            client_secret: Client secret (confidential clients).
            client_assertion: JWT for ``private_key_jwt`` auth.
            client_assertion_type: Assertion type URN (required with ``client_assertion``).
            token_endpoint: Optional token endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.

        Returns:
            Token response dict (``access_token``, ``id_token``, ``expires_in``, etc.).
        """
        endpoint = self._resolve_token_endpoint(token_endpoint)  # type: ignore[attr-defined]
        cert_param = self._get_cert_param()  # type: ignore[attr-defined]

        extra: dict[str, Any] = {}
        if authorization_details is not None:
            extra["authorization_details"] = (
                json.dumps(authorization_details)
                if not isinstance(authorization_details, str)
                else authorization_details
            )
        if extra_params:
            extra.update(extra_params)

        try:
            if client_assertion:
                oauth_client = OAuth2Client(
                    client_id=client_id,
                    token_endpoint=endpoint,
                    timeout=self.timeout,  # type: ignore[attr-defined]
                    verify=self.verify_ssl,  # type: ignore[attr-defined]
                    cert=cert_param,
                    token_endpoint_auth_method="none",
                )
                token = oauth_client.fetch_token(
                    url=endpoint,
                    grant_type="authorization_code",
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                    client_assertion=client_assertion,
                    client_assertion_type=(client_assertion_type or CLIENT_ASSERTION_TYPE_JWT),
                    **extra,
                )
            elif client_secret:
                oauth_client = OAuth2Client(
                    client_id=client_id,
                    client_secret=client_secret,
                    token_endpoint=endpoint,
                    timeout=self.timeout,  # type: ignore[attr-defined]
                    verify=self.verify_ssl,  # type: ignore[attr-defined]
                    cert=cert_param,
                    token_endpoint_auth_method="client_secret_post",
                )
                token = oauth_client.fetch_token(
                    url=endpoint,
                    grant_type="authorization_code",
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                    **extra,
                )
            else:
                # Public client — pass client_id explicitly in the body
                oauth_client = OAuth2Client(
                    client_id=client_id,
                    token_endpoint=endpoint,
                    timeout=self.timeout,  # type: ignore[attr-defined]
                    verify=self.verify_ssl,  # type: ignore[attr-defined]
                    cert=cert_param,
                    token_endpoint_auth_method="none",
                )
                token = oauth_client.fetch_token(
                    url=endpoint,
                    grant_type="authorization_code",
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                    client_id=client_id,
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
