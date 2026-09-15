"""The publisher uses the customer verifier's exact canonicalization code."""

from stig_audit_pro.licensing.canonicalize import (
    CanonicalizationError,
    canonicalize_license,
)

__all__ = ["CanonicalizationError", "canonicalize_license"]
