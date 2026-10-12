# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Device Authorization Grant (RFC 8628).
"""

import json
import time
from typing import Any, Callable, Optional

import httpx

from ibm_verify.oauth2.core.errors.errors import VerifyError


class DeviceCodeMixin:
    """Mixin that adds the Device Authorization Grant (RFC 8628).

    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    def request_device_code(
        self,
        client_id: str,
        scope: str = "openid profile email",
        client_secret: Optional[str] = None,
        device_auth_endpoint: Optional[str] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Start the Device Authorization flow — Step 1 (RFC 8628).

        Args:
            client_id: OAuth client ID.
            scope: Space-separated scopes (default: ``"openid profile email"``).
            client_secret: Client secret for confidential clients.
            device_auth_endpoint: Optional device authorization endpoint override.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Encoded as a JSON string in the request body.
            extra_params: Additional parameters to include in the request body.

        Returns:
            Dict with ``device_code``, ``user_code``, ``verification_uri``,
            ``expires_in``, and ``interval``.
        """
        endpoint = self._resolve_device_auth_endpoint(device_auth_endpoint)  # type: ignore[attr-defined]

        data: dict[str, Any] = {"scope": scope, "client_id": client_id}
        headers: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
        if client_secret:
            # IBM Verify uses client_secret_post: both client_id and client_secret go in
            # the request body.  Basic auth is rejected with CSIAQ0330E.
            data["client_secret"] = client_secret
        if authorization_details is not None:
            data["authorization_details"] = (
                json.dumps(authorization_details)
                if not isinstance(authorization_details, str)
                else authorization_details
            )
        if extra_params:
            data.update(extra_params)

        try:
            response = self._http_client.post(  # type: ignore[attr-defined]
                endpoint, data=data, headers=headers
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _body: dict = {}
            try:
                _body = exc.response.json()
            except Exception:
                pass
            _error = _body.get("error", "")
            _desc = _body.get("error_description", "")
            _hint = (
                " Hint: if this is a public client, remove IBM_DEVICE_CLIENT_SECRET "
                "from .env (or pass client_secret=None)."
                if exc.response.status_code == 401 and _error == "invalid_client"
                else ""
            )
            raise VerifyError(
                message=str(exc) + _hint,
                status_code=exc.response.status_code,
                error=_error,
                error_description=_desc,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=str(exc)) from exc
        return response.json()

    def poll_device_token(
        self,
        client_id: str,
        device_code: str,
        interval: int = 5,
        expires_in: int = 300,
        client_secret: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        extra_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Poll for a token until the user approves — Step 2 of Device flow (RFC 8628).

        Blocks until approved, expired, or denied.

        Args:
            client_id: OAuth client ID.
            device_code: ``device_code`` from :meth:`request_device_code`.
            interval: Seconds between polls (default: 5).
            expires_in: Device code lifetime in seconds (default: 300).
            client_secret: Client secret for confidential clients.
            token_endpoint: Optional token endpoint override.
            extra_params: Additional parameters to include in the token request body.

        Returns:
            Token response dict (``access_token``, ``id_token``, ``expires_in``, etc.).

        Raises:
            VerifyError: Device code expired, user denied, network error, or
                unexpected token endpoint error.
        """
        endpoint = self._resolve_token_endpoint(token_endpoint)  # type: ignore[attr-defined]
        deadline = time.time() + expires_in
        poll_interval = interval

        data: dict[str, Any] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id,
        }
        headers: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
        if client_secret:
            # IBM Verify uses client_secret_post: client_secret goes in the request body.
            # Basic auth is rejected with CSIAQ0330E.
            data["client_secret"] = client_secret
        if extra_params:
            data.update(extra_params)

        while time.time() < deadline:
            try:
                response = self._http_client.post(  # type: ignore[attr-defined]
                    endpoint, data=data, headers=headers
                )
            except httpx.RequestError as exc:
                raise VerifyError(message=str(exc)) from exc

            result = response.json()

            if "access_token" in result:
                return dict(result)

            error = result.get("error", "")
            description = result.get("error_description", "no description")

            if error == "authorization_pending":
                time.sleep(poll_interval)
                continue
            elif error == "slow_down":
                poll_interval += 5
                time.sleep(poll_interval)
            elif error == "expired_token":
                raise VerifyError(
                    message="Device code expired before the user completed authentication.",
                    error=error,
                    error_description=description,
                )
            elif error == "access_denied":
                raise VerifyError(
                    message="User denied the device authorization request.",
                    error=error,
                    error_description=description,
                )
            else:
                raise VerifyError(
                    message=f"Device token polling failed: {error} — {description}",
                    error=error,
                    error_description=description,
                )

        raise VerifyError(
            message="Device code polling timed out (deadline exceeded).",
            error="expired_token",
        )

    def device_authorization_flow(
        self,
        client_id: str,
        scope: str = "openid profile email",
        client_secret: Optional[str] = None,
        device_auth_endpoint: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        on_user_code: Optional[Callable[[dict[str, Any]], None]] = None,
        authorization_details: Optional[Any] = None,
        extra_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Run the complete Device Authorization flow (RFC 8628).

        Convenience wrapper around :meth:`request_device_code` +
        :meth:`poll_device_token`.

        Args:
            client_id: OAuth client ID.
            scope: Space-separated scopes (default: ``"openid profile email"``).
            client_secret: Client secret for confidential clients.
            device_auth_endpoint: Optional device authorization endpoint override.
            token_endpoint: Optional token endpoint override.
            on_user_code: Optional callback ``(device_data: dict) -> None`` — called
                before polling so the caller can display ``user_code`` /
                ``verification_uri``.
            authorization_details: Rich authorization request object (RAR, RFC 9396).
                Passed through to :meth:`request_device_code`.
            extra_params: Additional parameters passed through to both
                :meth:`request_device_code` and :meth:`poll_device_token`.

        Returns:
            Token response dict (``access_token``, ``id_token``, etc.).
        """
        device_data = self.request_device_code(
            client_id=client_id,
            scope=scope,
            client_secret=client_secret,
            device_auth_endpoint=device_auth_endpoint,
            authorization_details=authorization_details,
            extra_params=extra_params,
        )

        if on_user_code is not None:
            on_user_code(device_data)

        return self.poll_device_token(
            client_id=client_id,
            device_code=device_data["device_code"],
            interval=device_data.get("interval", 5),
            expires_in=device_data.get("expires_in", 300),
            client_secret=client_secret,
            token_endpoint=token_endpoint,
            extra_params=extra_params,
        )
