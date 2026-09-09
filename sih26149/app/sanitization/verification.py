"""
Sanitization verification.
Reads back the target image to verify that blocks are completely zeroed.
Returns VERIFIED_WITHIN_SCOPE upon complete zero verification.
"""
import os
from app.core.classification import EvidenceClassification, ClassifiedResult
from app.sanitization.scope import get_scope_record


def verify_sanitization(image_path: str, chunk_size: int = 65536) -> ClassifiedResult:
    """Verify that target image contains only zero bytes."""
    if not os.path.exists(image_path):
        return ClassifiedResult(
            classification=EvidenceClassification.FAILED,
            explanation='Verification failed: Target image file missing',
            details={'image_path': image_path},
        )

    total_bytes = 0
    non_zero_found = False

    with open(image_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            if any(b != 0 for b in chunk):
                non_zero_found = True
                break

    if non_zero_found:
        return ClassifiedResult(
            classification=EvidenceClassification.FAILED,
            explanation='Sanitization verification FAILED: Non-zero bytes discovered in target area',
            details={'bytes_checked': total_bytes, 'all_zeros': False},
        )

    scope_record = get_scope_record()
    return ClassifiedResult(
        classification=EvidenceClassification.VERIFIED_WITHIN_SCOPE,
        explanation=f'Sanitization VERIFIED WITHIN SCOPE: All {total_bytes} bytes verified zeroed. '
                    f'{scope_record["scope_statement"]}',
        details={
            'bytes_verified_zero': total_bytes,
            'scope': scope_record,
        },
    )
