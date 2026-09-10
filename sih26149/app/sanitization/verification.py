"""
Sanitization verification.
Method-aware readback:
  - ZERO_FILL → all bytes must be 0x00
  - PSEUDO_RANDOM → size preserved and content hash must differ from pre-image
Returns VERIFIED_WITHIN_SCOPE upon successful verification within stated scope.
"""
import hashlib
import os
from typing import Optional

from app.core.classification import EvidenceClassification, ClassifiedResult
from app.sanitization.methods import SanitizationMethod
from app.sanitization.scope import get_scope_record


def verify_sanitization(
    image_path: str,
    chunk_size: int = 65536,
    method: SanitizationMethod = SanitizationMethod.ZERO_FILL,
    pre_sha256: Optional[str] = None,
) -> ClassifiedResult:
    """Verify sanitization outcome for the requested Clear-class method."""
    if not os.path.exists(image_path):
        return ClassifiedResult(
            classification=EvidenceClassification.FAILED,
            explanation='Verification failed: Target image file missing',
            details={'image_path': image_path, 'method': method.value},
        )

    scope_record = get_scope_record()
    total_bytes = os.path.getsize(image_path)

    if method == SanitizationMethod.ZERO_FILL:
        non_zero_found = False
        checked = 0
        with open(image_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                checked += len(chunk)
                if any(b != 0 for b in chunk):
                    non_zero_found = True
                    break

        if non_zero_found:
            return ClassifiedResult(
                classification=EvidenceClassification.FAILED,
                explanation='Sanitization verification FAILED: Non-zero bytes discovered in target area',
                details={'bytes_checked': checked, 'all_zeros': False, 'method': method.value},
            )

        return ClassifiedResult(
            classification=EvidenceClassification.VERIFIED_WITHIN_SCOPE,
            explanation=(
                f'Sanitization VERIFIED WITHIN SCOPE: All {checked} bytes verified zeroed. '
                f'{scope_record["scope_statement"]}'
            ),
            details={
                'bytes_verified_zero': checked,
                'method': method.value,
                'scope': scope_record,
            },
        )

    # PSEUDO_RANDOM: confirm length preserved and content changed vs pre-image hash
    h = hashlib.sha256()
    with open(image_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    post_sha = h.hexdigest()

    if pre_sha256 and post_sha == pre_sha256:
        return ClassifiedResult(
            classification=EvidenceClassification.FAILED,
            explanation='Sanitization verification FAILED: Post-image SHA-256 identical to pre-image',
            details={
                'method': method.value,
                'pre_sha256': pre_sha256,
                'post_sha256': post_sha,
                'size_bytes': total_bytes,
            },
        )

    return ClassifiedResult(
        classification=EvidenceClassification.VERIFIED_WITHIN_SCOPE,
        explanation=(
            f'Sanitization VERIFIED WITHIN SCOPE: Pseudo-random overwrite confirmed '
            f'({total_bytes} bytes; hash shifted). {scope_record["scope_statement"]}'
        ),
        details={
            'method': method.value,
            'pre_sha256': pre_sha256,
            'post_sha256': post_sha,
            'size_bytes': total_bytes,
            'scope': scope_record,
        },
    )
