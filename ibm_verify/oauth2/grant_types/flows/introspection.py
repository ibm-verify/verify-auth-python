# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Token Introspection (RFC 7662).
"""

from typing import Any, Callable, Optional, Union
from urllib.parse import urlencode

import httpx
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.httpx_client import OAuth2Client

from ibm_verify.oauth2.core.errors.errors import VerifyError
from ibm_verify.oauth2.grant_types.constants import CLIENT_ASSERTION_TYPE_JWT


class IntrospectMixin:
    """Mixin that adds token introspection (RFC 7662).

    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def introspect_token(
        self,
        token: str,
        op_name: str = "default",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client_assertion: Optional[Union[str, Callable[[], str]]] = None,
        client_assertion_type: Optional[str] = None,
        token_type_hint: Optional[str] = None,
        authorization_header: Optional[str] = None,
        introspect_endpoint: Optional[str] = None,
    ) -> dict[str, Any]:
        """Introspect an OAuth 2.0 / OIDC token (RFC 7662).

        Args:
            token: Token to introspect.
            op_name: OIDC provider name for endpoint resolution (default: ``"default"``).
            client_id: Client ID for authentication.
            client_secret: Client secret for authentication.
            client_assertion: JWT for ``private_key_jwt`` authentication. Sent with
                ``client_id`` in the request body.
                Also accepts a zero-argument callable returning a fresh assertion
                (recommended with DPoP, so a nonce retry gets a new assertion).
            client_assertion_type: Assertion type URN (default: jwt-bearer when
                ``client_assertion`` is given).
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

        auth_method = "none"  # also used for private_key_jwt: credentials go in the body
        if client_assertion:
            pass
        elif client_secret:
            auth_method = "client_secret_post"
        elif authorization_header:
            auth_method = "client_secret_basic"

        client = OAuth2Client(
            client_id=client_id,
            client_secret=None if client_assertion else client_secret,
            token_introspection_endpoint=introspect_url,
            timeout=self.timeout,  # type: ignore[attr-defined]
            verify=self.verify_ssl,  # type: ignore[attr-defined]
            cert=self._get_cert_param(),  # type: ignore[attr-defined]
            token_endpoint_auth_method=auth_method,
        )

        # authlib's introspect_token() only forwards ``body`` (a form string); any
        # other keyword such as ``data=`` is silently dropped.
        body: dict[str, Any] = {}
        if client_assertion:
            body["client_assertion"] = (
                client_assertion() if callable(client_assertion) else client_assertion
            )
            body["client_assertion_type"] = client_assertion_type or CLIENT_ASSERTION_TYPE_JWT

        headers: dict[str, str] = {}
        if authorization_header:
            headers["Authorization"] = authorization_header

        try:
            result = client.introspect_token(
                url=introspect_url,
                token=token,
                token_type_hint=token_type_hint,
                body=urlencode(body),
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
        finally:
            client.close()

        if hasattr(result, "raise_for_status"):
            try:
                result.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise VerifyError(
                    message=str(exc),
                    status_code=exc.response.status_code,
                ) from exc
        if hasattr(result, "json"):
            try:
                data: dict[str, Any] = result.json()
            except ValueError as exc:
                raise VerifyError(
                    message=f"Invalid introspection response: {exc}",
                    status_code=getattr(result, "status_code", None),
                ) from exc
            return data
        return dict(result) if result else {}
