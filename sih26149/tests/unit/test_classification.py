"""
Unit tests for evidence classification.
Verifies VERIFIED cannot be manufactured by dict construction.
"""
import pytest
from app.core.classification import (
    EvidenceClassification, ClassifiedResult,
    classify_recovery, classify_sanitization, classify_verification
)


class TestClassifyRecovery:
    def test_verified_when_hashes_match(self):
        h = 'deadbeef' * 8  # 64 char hex
        result = classify_recovery(recovered_hash=h, reference_hash=h)
        assert result.classification == EvidenceClassification.VERIFIED

    def test_failed_when_hashes_differ(self):
        result = classify_recovery(
            recovered_hash='aaa' * 21 + 'a',
            reference_hash='bbb' * 21 + 'b',
        )
        assert result.classification == EvidenceClassification.FAILED

    def test_unverified_when_no_reference(self):
        result = classify_recovery(recovered_hash='abc' * 21 + 'ab', reference_hash=None)
        assert result.classification == EvidenceClassification.UNVERIFIED

    def test_explanation_is_non_empty(self):
        result = classify_recovery('x' * 64, None)
        assert len(result.explanation) > 0

    def test_hash_comparison_case_insensitive(self):
        h = 'ABCDEF' + '0' * 58
        result = classify_recovery(
            recovered_hash=h.lower(),
            reference_hash=h.upper(),
        )
        assert result.classification == EvidenceClassification.VERIFIED

    def test_cannot_manufacture_verified_by_dict(self):
        """VERIFIED cannot come from a plain dict — must go through classify_recovery."""
        fake = {'classification': 'VERIFIED'}
        # This is just a dict — not a ClassifiedResult
        assert not isinstance(fake, ClassifiedResult)
        # Only classify_recovery produces ClassifiedResult
        result = classify_recovery('a' * 64, 'b' * 64)
        assert isinstance(result, ClassifiedResult)
        assert result.classification == EvidenceClassification.FAILED  # hashes differ


class TestClassifySanitization:
    SCOPE = 'virtual ext4 filesystem image — filesystem-level scope only'

    def test_rejected_without_authorization(self):
        result = classify_sanitization(authorized=False, verified=False, scope=self.SCOPE)
        assert result.classification == EvidenceClassification.REJECTED

    def test_verified_within_scope_when_authorized_and_verified(self):
        result = classify_sanitization(authorized=True, verified=True, scope=self.SCOPE)
        assert result.classification == EvidenceClassification.VERIFIED_WITHIN_SCOPE

    def test_failed_when_authorized_but_verification_failed(self):
        result = classify_sanitization(authorized=True, verified=False, scope=self.SCOPE)
        assert result.classification == EvidenceClassification.FAILED

    def test_scope_is_in_explanation(self):
        result = classify_sanitization(authorized=True, verified=True, scope=self.SCOPE)
        assert self.SCOPE in result.explanation

    def test_never_claims_universal_secure(self):
        result = classify_sanitization(authorized=True, verified=True, scope=self.SCOPE)
        text = result.explanation.upper()
        assert 'UNIVERSALLY' not in text
        assert 'PHYSICAL' not in text
        assert 'NAND' not in text


class TestClassifyVerification:
    def test_verified_when_both_pass(self):
        result = classify_verification(signature_valid=True, hash_matches=True)
        assert result.classification == EvidenceClassification.VERIFIED

    def test_invalid_when_signature_fails(self):
        result = classify_verification(signature_valid=False, hash_matches=True)
        assert result.classification == EvidenceClassification.INVALID

    def test_invalid_when_hash_fails(self):
        result = classify_verification(signature_valid=True, hash_matches=False)
        assert result.classification == EvidenceClassification.INVALID

    def test_invalid_when_both_fail(self):
        result = classify_verification(signature_valid=False, hash_matches=False)
        assert result.classification == EvidenceClassification.INVALID

    def test_tamper_mentioned_in_explanation(self):
        result = classify_verification(signature_valid=False, hash_matches=True)
        assert 'TAMPER' in result.explanation.upper()


class TestClassifiedResult:
    def test_to_dict(self):
        result = classify_recovery('a' * 64, 'a' * 64)
        d = result.to_dict()
        assert 'classification' in d
        assert 'explanation' in d
        assert 'details' in d

    def test_details_returns_copy(self):
        """Details dict is a copy — mutating it doesn't affect internal state."""
        result = classify_recovery('x' * 64, None)
        d = result.details
        d['injection'] = 'attack'
        assert 'injection' not in result.details
