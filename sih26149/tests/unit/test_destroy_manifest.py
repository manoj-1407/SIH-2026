"""
Tests for NIST SP 800-88 Rev. 2 DESTROY branch — Physical Disposal Manifest.
"""
import json
import pytest
from app.sanitization.destroy_manifest import (
    generate_disposal_manifest,
    generate_manifest_html,
    DESTRUCTION_MATRIX,
    DestructionMethod,
    VerificationRequirement,
    PhysicalDisposalManifest,
)
from app.sanitization.device_detector import MediaType


class TestDestructionMatrix:
    """Verify the destruction matrix covers all media types."""

    def test_all_media_types_covered(self):
        """Every MediaType enum value must have a destruction matrix entry."""
        for mt in MediaType:
            assert mt in DESTRUCTION_MATRIX, f"Missing DESTRUCTION_MATRIX entry for {mt}"

    def test_each_entry_has_required_fields(self):
        for mt, entry in DESTRUCTION_MATRIX.items():
            assert "primary_method" in entry, f"Missing primary_method for {mt}"
            assert "secondary_methods" in entry, f"Missing secondary_methods for {mt}"
            assert "reason_destroy_required" in entry, f"Missing reason for {mt}"
            assert "verification" in entry, f"Missing verification for {mt}"
            assert isinstance(entry["primary_method"], DestructionMethod)
            assert all(isinstance(m, DestructionMethod) for m in entry["secondary_methods"])

    def test_hdd_gets_degauss(self):
        """HDD should recommend DEGAUSS as primary destruction method."""
        entry = DESTRUCTION_MATRIX[MediaType.ROTATIONAL_HDD]
        assert entry["primary_method"] == DestructionMethod.DEGAUSS

    def test_ssd_not_degauss(self):
        """SSD/NVMe should NOT recommend DEGAUSS — no magnetic domains."""
        for mt in [MediaType.SATA_SSD, MediaType.NVME_SSD, MediaType.USB_FLASH]:
            entry = DESTRUCTION_MATRIX[mt]
            assert entry["primary_method"] != DestructionMethod.DEGAUSS, (
                f"{mt} should not use DEGAUSS"
            )

    def test_certificate_of_destruction_always_present(self):
        """Every media type verification should include CERTIFICATE_OF_DESTRUCTION."""
        for mt, entry in DESTRUCTION_MATRIX.items():
            certs = [v for v in entry["verification"] if v == VerificationRequirement.CERTIFICATE_OF_DESTRUCTION]
            assert len(certs) == 1, f"{mt} missing CERTIFICATE_OF_DESTRUCTION"


class TestGenerateDisposalManifest:
    """Test the manifest generation function."""

    def _generate_basic(self, **kwargs):
        defaults = dict(
            case_id="TEST-CASE-001",
            target_path="evidence.img",
            operator_id="AUTH-001",
            operator_name="Test Officer",
            authorization_reason="Court order for destruction",
        )
        defaults.update(kwargs)
        return generate_disposal_manifest(**defaults)

    def test_returns_manifest_object(self):
        m = self._generate_basic()
        assert isinstance(m, PhysicalDisposalManifest)

    def test_manifest_id_format(self):
        m = self._generate_basic()
        assert m.manifest_id.startswith("DESTROY-")
        assert len(m.manifest_id) > 12

    def test_case_id_preserved(self):
        m = self._generate_basic(case_id="MY-CASE-999")
        assert m.case_id == "MY-CASE-999"

    def test_operator_recorded(self):
        m = self._generate_basic(operator_id="OP-7", operator_name="Inspector Shah")
        assert m.operator["id"] == "OP-7"
        assert m.operator["name"] == "Inspector Shah"

    def test_items_populated(self):
        m = self._generate_basic()
        assert len(m.items) == 1
        item = m.items[0]
        assert item["item_id"].startswith("ITEM-")
        assert "destruction_method" in item
        assert "reason_destroy_required" in item

    def test_serial_number_optional(self):
        m = self._generate_basic(serial_number=None)
        assert m.items[0]["serial_number"] is None

    def test_serial_number_preserved(self):
        m = self._generate_basic(serial_number="WD-ABC123")
        assert m.items[0]["serial_number"] == "WD-ABC123"

    def test_image_file_gets_virtual_disk_classification(self):
        m = self._generate_basic(target_path="evidence.img")
        assert m.items[0]["media_capability"]["media_type"] == "VIRTUAL_DISK_IMAGE"

    def test_classification_level_default(self):
        m = self._generate_basic()
        assert m.classification_level == "CONFIDENTIAL"

    def test_classification_level_override(self):
        m = self._generate_basic(classification_level="SECRET")
        assert m.classification_level == "SECRET"

    def test_witnesses_empty_by_default(self):
        m = self._generate_basic()
        assert m.witnesses == []

    def test_witnesses_populated(self):
        m = self._generate_basic(witnesses=[
            {"name": "Inspector A", "id": "W-001", "role": "Case Officer", "org": "NTRO"},
        ])
        assert len(m.witnesses) == 1
        assert m.witnesses[0]["witness_name"] == "Inspector A"

    def test_pre_destruction_checklist_present(self):
        m = self._generate_basic()
        assert len(m.pre_destruction_checklist) >= 5
        assert all("requirement" in c for c in m.pre_destruction_checklist)
        assert all(c["completed"] is False for c in m.pre_destruction_checklist)

    def test_chain_of_custody_events(self):
        m = self._generate_basic()
        events = [e["event"] for e in m.chain_of_custody]
        assert "MANIFEST_GENERATED" in events
        assert "PENDING_DESTRUCTION" in events
        assert "DESTRUCTION_COMPLETED" in events

    def test_manifest_hash_is_sha256_hex(self):
        m = self._generate_basic()
        assert len(m.manifest_hash) == 64
        int(m.manifest_hash, 16)  # Should not raise — valid hex

    def test_legal_citations_include_nist(self):
        m = self._generate_basic()
        nist_cited = any("NIST" in c for c in m.legal_citations)
        assert nist_cited

    def test_legal_citations_include_bsa(self):
        m = self._generate_basic()
        bsa_cited = any("BSA" in c or "Bharatiya" in c for c in m.legal_citations)
        assert bsa_cited

    def test_to_dict_roundtrip(self):
        m = self._generate_basic()
        d = m.to_dict()
        assert isinstance(d, dict)
        assert d["manifest_id"] == m.manifest_id
        assert d["case_id"] == m.case_id

    def test_nist_reference_value(self):
        m = self._generate_basic()
        assert "800-88" in m.nist_reference
        assert "Destroy" in m.nist_reference

    def test_scope_statement_mentions_destroy(self):
        m = self._generate_basic()
        assert "DESTROY" in m.scope_statement

    def test_disclaimer_mentions_documentation(self):
        m = self._generate_basic()
        assert "documentation" in m.disclaimer.lower()


class TestGenerateManifestHtml:
    """Test the HTML rendering of the manifest."""

    def _get_html(self, **kwargs):
        defaults = dict(
            case_id="HTML-TEST-001",
            target_path="disk.raw",
            operator_id="AUTH-002",
            operator_name="HTML Officer",
            authorization_reason="Testing HTML generation",
        )
        defaults.update(kwargs)
        m = generate_disposal_manifest(**defaults)
        return generate_manifest_html(m), m

    def test_returns_valid_html(self):
        html, _ = self._get_html()
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_contains_manifest_id(self):
        html, m = self._get_html()
        assert m.manifest_id in html

    def test_contains_nist_reference(self):
        html, _ = self._get_html()
        assert "NIST SP 800-88" in html
        assert "DESTROY" in html

    def test_contains_classification_level(self):
        html, _ = self._get_html(classification_level="SECRET")
        assert "SECRET" in html

    def test_contains_operator_info(self):
        html, _ = self._get_html(operator_name="Dr. Verma")
        assert "Dr. Verma" in html

    def test_contains_checklist_table(self):
        html, _ = self._get_html()
        assert "Pre-Destruction Checklist" in html
        assert "☐" in html  # Checkbox symbol

    def test_contains_signature_blocks(self):
        html, _ = self._get_html()
        assert "Authorizing Officer" in html
        assert "Destruction Facility Operator" in html

    def test_contains_sha256_hash(self):
        html, m = self._get_html()
        assert m.manifest_hash in html

    def test_print_media_css(self):
        html, _ = self._get_html()
        assert "@media print" in html

    def test_witness_placeholder_when_none(self):
        html, _ = self._get_html(witnesses=None)
        assert "Witness records to be added" in html

    def test_witness_rows_when_provided(self):
        html, _ = self._get_html(witnesses=[
            {"name": "Inspector Ray", "id": "W-999", "role": "Lab Head", "org": "CBI"},
        ])
        assert "Inspector Ray" in html
        assert "Lab Head" in html
