# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Token Introspection (RFC 7662).
"""

from typing import Any, Dict, Optional

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from authlib.common.errors import AuthlibBaseError

from oauth2.core.errors.errors import VerifyError


class IntrospectMixin:
    """Mixin that adds token introspection (RFC 7662).

    Requires :class:`~oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def introspect_token(
        self,
        token: str,
        op_name: str = "default",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client_assertion: Optional[str] = None,
        client_assertion_type: Optional[str] = None,
        token_type_hint: Optional[str] = None,
        authorization_header: Optional[str] = None,
        introspect_endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Introspect an OAuth 2.0 / OIDC token (RFC 7662).

        Args:
            token: Token to introspect.
            op_name: OIDC provider name for endpoint resolution (default: ``"default"``).
            client_id: Client ID for authentication.
            client_secret: Client secret for authentication.
            client_assertion: JWT for ``private_key_jwt`` authentication.
            client_assertion_type: Assertion type URN.
            token_type_hint: ``"access_token"`` or ``"refresh_token"``.
            authorization_header: ``Authorization: Basic …`` header — alternative to
                client_id/secret.
            introspect_endpoint: Optional introspection endpoint override.

        Returns:
            Dict with ``active`` (bool), ``scope``, ``client_id``, ``username``,
            ``exp``, ``sub``, ``iss``, etc.
        """
        introspect_url = self._resolve_introspect_endpoint(  # type: ignore[attr-defined]
            caller_endpoint=introspect_endpoint, op_name=op_name
        )

        auth_method = "none"
        if client_secret:
            auth_method = "client_secret_post"
        elif authorization_header:
            auth_method = "client_secret_basic"

        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            token_introspection_endpoint=introspect_url,
            timeout=self.timeout,  # type: ignore[attr-defined]
            verify=self.verify_ssl,  # type: ignore[attr-defined]
            token_endpoint_auth_method=auth_method,
        )

        data: Dict[str, Any] = {}
        if client_assertion:
            data["client_assertion"] = client_assertion
        if client_assertion_type:
            data["client_assertion_type"] = client_assertion_type

        headers: Dict[str, str] = {}
        if authorization_header:
            headers["Authorization"] = authorization_header

        try:
            result = client.introspect_token(
                url=introspect_url,
                token=token,
                token_type_hint=token_type_hint,
                data=data,
                headers=headers,
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

        if hasattr(result, "raise_for_status"):
            try:
                result.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise VerifyError(
                    message=str(exc),
                    status_code=exc.response.status_code,
                ) from exc
        if hasattr(result, "json"):
            return result.json()
        return dict(result) if result else {}
