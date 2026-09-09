"""
Structural evidence classification.

Outcome CANNOT be set by constructing a dict manually.
Classification is tied to actual verification conditions.

Outcomes:
  VERIFIED            — recovered hash matches trusted reference
  PARTIAL             — some but not all verifiable conditions met
  FAILED              — operation failed or hash mismatch
  UNVERIFIED          — operation succeeded but no trusted reference available
  VERIFIED_WITHIN_SCOPE — sanitization verified within documented technical scope
  REJECTED            — authorization was not provided
  INVALID             — cryptographic verification failed (tamper detected)
"""
from enum import Enum


class EvidenceClassification(str, Enum):
    VERIFIED = 'VERIFIED'
    PARTIAL = 'PARTIAL'
    FAILED = 'FAILED'
    UNVERIFIED = 'UNVERIFIED'
    VERIFIED_WITHIN_SCOPE = 'VERIFIED_WITHIN_SCOPE'
    REJECTED = 'REJECTED'
    INVALID = 'INVALID'


class ClassifiedResult:
    """A classification that carries its evidence — cannot be faked by dict."""

    def __init__(
        self,
        classification: EvidenceClassification,
        explanation: str,
        details: dict | None = None,
    ):
        self._classification = classification
        self._explanation = explanation
        self._details = details or {}
        self._sealed = True  # marker

    @property
    def classification(self) -> EvidenceClassification:
        return self._classification

    @property
    def explanation(self) -> str:
        return self._explanation

    @property
    def details(self) -> dict:
        return dict(self._details)

    def to_dict(self) -> dict:
        return {
            'classification': self._classification.value,
            'explanation': self._explanation,
            'details': self._details,
        }

    def __repr__(self):
        return f'ClassifiedResult({self._classification.value})'


# ── Recovery classification ──────────────────────────────────────

def classify_recovery(
    recovered_hash: str,
    reference_hash: str | None,
) -> ClassifiedResult:
    """
    Classify a recovery result.

    If reference_hash is provided:
        match   -> VERIFIED
        no match -> FAILED

    If reference_hash is None:
        -> UNVERIFIED (recovery succeeded but certainty cannot be established)

    NEVER produces VERIFIED without an actual matching reference.
    """
    if reference_hash is None:
        return ClassifiedResult(
            EvidenceClassification.UNVERIFIED,
            'Recovery completed, but no trusted reference hash was available '
            'to establish content identity.',
            {'recovered_sha256': recovered_hash, 'reference_sha256': None},
        )

    if recovered_hash.lower() == reference_hash.lower():
        return ClassifiedResult(
            EvidenceClassification.VERIFIED,
            'Recovered content SHA-256 matches trusted reference hash.',
            {'recovered_sha256': recovered_hash, 'reference_sha256': reference_hash},
        )
    else:
        return ClassifiedResult(
            EvidenceClassification.FAILED,
            'Recovered content SHA-256 does NOT match reference hash. '
            'Content may have been overwritten or corrupted.',
            {'recovered_sha256': recovered_hash, 'reference_sha256': reference_hash},
        )


# ── Sanitization classification ──────────────────────────────────

def classify_sanitization(
    authorized: bool,
    verified: bool,
    scope: str,
) -> ClassifiedResult:
    """
    Classify a sanitization result.

    Without authorization -> REJECTED
    With authorization and verification -> VERIFIED_WITHIN_SCOPE
    With authorization but verification failed -> FAILED

    NEVER produces UNIVERSALLY_SECURE or claims physical erasure.
    """
    if not authorized:
        return ClassifiedResult(
            EvidenceClassification.REJECTED,
            'Sanitization was not authorized. Operation blocked.',
            {'authorized': False},
        )

    if verified:
        return ClassifiedResult(
            EvidenceClassification.VERIFIED_WITHIN_SCOPE,
            f'Sanitization verified within the tested technical scope: {scope}',
            {'authorized': True, 'verified': True, 'scope': scope},
        )
    else:
        return ClassifiedResult(
            EvidenceClassification.FAILED,
            'Sanitization authorization was present but verification failed.',
            {'authorized': True, 'verified': False},
        )


# ── Signature verification classification ───────────────────────

def classify_verification(
    signature_valid: bool,
    hash_matches: bool,
) -> ClassifiedResult:
    """
    Classify cryptographic evidence verification.

    Both signature valid AND hash matches -> VERIFIED
    Either fails -> INVALID (tamper detected)
    """
    if signature_valid and hash_matches:
        return ClassifiedResult(
            EvidenceClassification.VERIFIED,
            'Ed25519 signature is valid. Evidence hash matches. '
            'No tampering detected.',
            {'signature_valid': True, 'hash_matches': True},
        )

    reasons = []
    if not signature_valid:
        reasons.append('Ed25519 signature verification failed')
    if not hash_matches:
        reasons.append('Evidence hash does not match signed content')

    return ClassifiedResult(
        EvidenceClassification.INVALID,
        'TAMPER DETECTED: ' + '; '.join(reasons) + '.',
        {'signature_valid': signature_valid, 'hash_matches': hash_matches},
    )
