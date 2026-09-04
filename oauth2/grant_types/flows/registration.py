# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — Dynamic Client Registration (RFC 7591 / RFC 7592).

``DcrMixin`` provides four lifecycle operations:

* :meth:`register_client`  — POST  to registration endpoint (RFC 7591)
* :meth:`read_client`      — GET   to client configuration endpoint (RFC 7592)
* :meth:`update_client`    — PUT   to client configuration endpoint (RFC 7592)
* :meth:`delete_client`    — DELETE to client configuration endpoint (RFC 7592)

The registration endpoint is resolved in priority order:
  caller override → discovery (``registration_endpoint``) → default path.

The client configuration endpoint (read/update/delete) is always the
``registration_client_uri`` returned in the registration response, or an
explicit ``registration_endpoint`` override supplied by the caller.
"""

from typing import Any, Optional

import httpx

from oauth2.core.errors.errors import VerifyError
from oauth2.grant_types.constants import DEFAULT_REGISTRATION_PATH


class DcrMixin:
    """Mixin that adds Dynamic Client Registration (RFC 7591 / RFC 7592).

    Requires :class:`~oauth2.grant_types.base.OAuthBase` in the MRO.
    """

    # ── Endpoint resolver ─────────────────────────────────────────────────────

    def _resolve_registration_endpoint(
        self,
        caller_endpoint: Optional[str] = None,
    ) -> str:
        """Priority: caller override → discovery → default path."""
        if caller_endpoint:
            return caller_endpoint
        if self._provider_metadata:  # type: ignore[attr-defined]
            discovered = self._provider_metadata.get("registration_endpoint")  # type: ignore[attr-defined]
            if discovered:
                return str(discovered)
        return f"{self.base_url}{DEFAULT_REGISTRATION_PATH}"  # type: ignore[attr-defined]

    # ── RFC 7591 — registration ───────────────────────────────────────────────

    def register_client(
        self,
        client_metadata: dict[str, Any],
        initial_access_token: Optional[str] = None,
        registration_endpoint: Optional[str] = None,
    ) -> dict[str, Any]:
        """Dynamically register a new OAuth client (RFC 7591).

        Args:
            client_metadata: Client metadata document as a dict.  Common fields:
                ``redirect_uris``, ``grant_types``, ``response_types``,
                ``client_name``, ``token_endpoint_auth_method``, ``scope``.
            initial_access_token: Bearer token authorising the registration
                request (required by most IBM Verify tenants).
            registration_endpoint: Explicit endpoint override — takes priority
                over discovery and the SDK default.

        Returns:
            Client information response dict containing at minimum
            ``client_id``, ``client_secret`` (for confidential clients),
            ``registration_access_token``, and ``registration_client_uri``.

        Raises:
            :class:`~oauth2.core.errors.errors.VerifyError`:
                On HTTP error or network failure.
        """
        endpoint = self._resolve_registration_endpoint(registration_endpoint)

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if initial_access_token:
            headers["Authorization"] = f"Bearer {initial_access_token}"

        try:
            response = self._http_client.post(  # type: ignore[attr-defined]
                endpoint,
                json=client_metadata,
                headers=headers,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            raise VerifyError(
                message=f"DCR register failed: {exc} | body={body}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=f"DCR register failed: {exc}") from exc

        return response.json()

    # ── RFC 7592 — read ───────────────────────────────────────────────────────

    def read_client(
        self,
        registration_access_token: str,
        registration_client_uri: str,
    ) -> dict[str, Any]:
        """Retrieve a registered client's metadata (RFC 7592 §4.1).

        Args:
            registration_access_token: Access token returned in the registration
                response (``registration_access_token`` field).
            registration_client_uri: URL returned in the registration response
                (``registration_client_uri`` field).

        Returns:
            Current client metadata dict.

        Raises:
            :class:`~oauth2.core.errors.errors.VerifyError`:
                On HTTP error or network failure.
        """
        try:
            response = self._http_client.get(  # type: ignore[attr-defined]
                registration_client_uri,
                headers={"Authorization": f"Bearer {registration_access_token}"},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            raise VerifyError(
                message=f"DCR read failed: {exc} | body={body}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=f"DCR read failed: {exc}") from exc

        return response.json()

    # ── RFC 7592 — update ─────────────────────────────────────────────────────

    def update_client(
        self,
        registration_access_token: str,
        registration_client_uri: str,
        client_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a registered client's metadata (RFC 7592 §4.2).

        The full metadata document must be supplied (PUT semantics — not PATCH).

        Args:
            registration_access_token: Registration access token.
            registration_client_uri: Client configuration endpoint URI.
            client_metadata: Complete replacement metadata document.

        Returns:
            Updated client metadata dict.

        Raises:
            :class:`~oauth2.core.errors.errors.VerifyError`:
                On HTTP error or network failure.
        """
        try:
            response = self._http_client.put(  # type: ignore[attr-defined]
                registration_client_uri,
                json=client_metadata,
                headers={
                    "Authorization": f"Bearer {registration_access_token}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            raise VerifyError(
                message=f"DCR update failed: {exc} | body={body}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=f"DCR update failed: {exc}") from exc

        return response.json()

    # ── RFC 7592 — delete ─────────────────────────────────────────────────────

    def delete_client(
        self,
        registration_access_token: str,
        registration_client_uri: str,
    ) -> None:
        """Delete a registered client (RFC 7592 §4.3).

        Args:
            registration_access_token: Registration access token.
            registration_client_uri: Client configuration endpoint URI.

        Returns:
            ``None`` on success (HTTP 204).

        Raises:
            :class:`~oauth2.core.errors.errors.VerifyError`:
                On HTTP error or network failure.
        """
        try:
            response = self._http_client.delete(  # type: ignore[attr-defined]
                registration_client_uri,
                headers={"Authorization": f"Bearer {registration_access_token}"},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            raise VerifyError(
                message=f"DCR delete failed: {exc} | body={body}",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.RequestError as exc:
            raise VerifyError(message=f"DCR delete failed: {exc}") from exc
