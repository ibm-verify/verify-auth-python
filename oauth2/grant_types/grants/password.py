"""
IBM Verify OAuth — Password Grant (RFC 6749 §4.3).

Resource Owner Password Credentials grant.
"""

import json
from typing import Any, Dict, Optional

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from authlib.common.errors import AuthlibBaseError

from oauth2.core.errors.errors import VerifyError


class PasswordGrantMixin:
    """Mixin that adds the Resource Owner Password Credentials grant.

    Requires :class:`~oauth2.grant_types.base.OAuthBase` in the MRO.
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
        extra_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Exchange username/password for tokens (RFC 6749 §4.3).

        Args:
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            username: Resource owner username.
            password: Resource owner password.
            authorization_header: ``Authorization`` header value.
            scope: Optional space-separated scope string.
            token_endpoint: Optional token endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the token request body.
            extra_params: Additional parameters to include in the token request body.

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
        )
        fetch_kwargs: Dict[str, Any] = dict(
            url=endpoint,
            grant_type="password",
            username=username,
            password=password,
            headers={"Authorization": authorization_header},
        )
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
        try:
            token = client.fetch_token(**fetch_kwargs)
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
