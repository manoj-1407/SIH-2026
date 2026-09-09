"""
Recovery result verification.

Classifies recovery outcome against an optional trusted reference hash.

RULE: Recovery success alone does NOT mean VERIFIED.
If no trusted ground truth exists -> UNVERIFIED.
Never manufacture certainty.
"""
from app.core.classification import classify_recovery, ClassifiedResult


def verify_recovery(
    recovered_sha256: str,
    reference_sha256: str | None,
) -> ClassifiedResult:
    """
    Verify a recovery result.

    If reference_sha256 provided:
        match   -> VERIFIED
        mismatch -> FAILED (content overwritten or corrupted)

    If reference_sha256 is None:
        -> UNVERIFIED (cannot establish content identity without ground truth)
    """
    return classify_recovery(
        recovered_hash=recovered_sha256,
        reference_hash=reference_sha256,
    )
