# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth 2.0 / OIDC Python SDK.

Public API::

    from ibm_verify.oauth2 import OAuthClient

``OAuthClient`` (in ``ibm_verify.oauth2.auth.client``) composes the individual grant
and flow mixins from ``ibm_verify.oauth2.grant_types`` into a single client. Advanced
users can import mixins, constants, and utilities directly from
``ibm_verify.oauth2.grant_types`` for custom compositions.
"""

from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError

__all__ = [
    "OAuthClient",
    "VerifyError",
]
