# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify SDK — core error type.
"""

from typing import Optional


class VerifyError(Exception):
    """Raised by IBM Verify SDK operations on HTTP or network failures.

    Args:
        message: Human-readable description of the error.
        status_code: HTTP status code, if the error originated from an HTTP response.
        error: OAuth error code (e.g. ``invalid_client``).
        error_description: Human-readable OAuth error description.
    """

    def __init__(
        self,
        message: str = "",
        status_code: Optional[int] = None,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error = error
        self.error_description = error_description

    def __str__(self) -> str:
        if (
            self.status_code is None
            and self.error is None
            and self.error_description is None
        ):
            return self.message
        parts = [self.message]
        if self.status_code is not None:
            parts.append(f"status_code={self.status_code}")
        if self.error is not None:
            parts.append(f"error={self.error!r}")
        if self.error_description is not None:
            parts.append(f"error_description={self.error_description!r}")
        return " | ".join(parts)

    def __repr__(self) -> str:
        parts = [f"message={self.message!r}"]
        if self.status_code is not None:
            parts.append(f"status_code={self.status_code}")
        if self.error is not None:
            parts.append(f"error={self.error!r}")
        if self.error_description is not None:
            parts.append(f"error_description={self.error_description!r}")
        return f"VerifyError({', '.join(parts)})"
