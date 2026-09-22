"""
NIST SP 800-88 Rev. 2 DESTROY Branch — Physical Disposal Manifest Generator.

When the device capability detector recommends DESTROY (i.e., media cannot
be cleared or purged through software — flash with inaccessible spare areas,
optical media, damaged platters, etc.), this module generates a structured,
court-admissible physical disposal manifest.

The manifest documents:
  1. Device identification and classification
  2. Reason Clear/Purge is insufficient
  3. Approved destruction method per media type (NIST SP 800-88 Rev. 2 Table A-1)
  4. Verification requirements post-destruction
  5. Chain-of-custody handoff record
  6. Witness/operator attestation blocks

This is NOT a physical destruction tool — it is a documentation generator
that ensures NIST-compliant paperwork accompanies the physical act.

Reference: NIST SP 800-88 Rev. 2 §2.5 Destroy
  "Destroy renders target data recovery infeasible using state of the art
   laboratory techniques and results in the subsequent inability to use
   the media for storage of data."
"""
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any

from app.sanitization.device_detector import (
    detect_media_type, DeviceCapability, MediaType, SanitizationLevel,
)


class DestructionMethod(str, Enum):
    """NIST SP 800-88 Rev. 2 Table A-1 approved destruction methods."""
    DISINTEGRATE = "DISINTEGRATE"       # Shred to ≤2mm particles
    INCINERATE   = "INCINERATE"         # Licensed incinerator, ≥1600°F
    PULVERIZE    = "PULVERIZE"          # Crush to deformation beyond recovery
    DEGAUSS      = "DEGAUSS"            # Magnetic media only (HDD platters)
    SHRED        = "SHRED"              # Cross-cut shredder per DIN 66399
    MELT         = "MELT"               # Optical media, SSD NAND wafers

    @property
    def description(self) -> str:
        return {
            self.DISINTEGRATE: "Shred media into particles ≤2mm in any dimension",
            self.INCINERATE:   "Burn in a licensed incinerator at ≥1600°F (871°C)",
            self.PULVERIZE:    "Crush/deform media beyond physical reconstruction",
            self.DEGAUSS:      "Apply magnetic field ≥7000 Oe (HDD platters only)",
            self.SHRED:        "Cross-cut shred per DIN 66399 Level H-5 or higher",
            self.MELT:         "Melt substrate in a licensed smelting facility",
        }[self]


class VerificationRequirement(str, Enum):
    """Post-destruction verification methods."""
    VISUAL_INSPECTION    = "VISUAL_INSPECTION"
    PARTICLE_SIZE_CHECK  = "PARTICLE_SIZE_CHECK"
    WEIGHT_COMPARISON    = "WEIGHT_COMPARISON"
    PHOTOGRAPHIC_RECORD  = "PHOTOGRAPHIC_RECORD"
    CERTIFICATE_OF_DESTRUCTION = "CERTIFICATE_OF_DESTRUCTION"


# ── Media → destruction method mapping ──────────────────────────────────────

DESTRUCTION_MATRIX: Dict[MediaType, Dict[str, Any]] = {
    MediaType.ROTATIONAL_HDD: {
        "primary_method": DestructionMethod.DEGAUSS,
        "secondary_methods": [DestructionMethod.SHRED, DestructionMethod.DISINTEGRATE],
        "reason_destroy_required": (
            "Rotational HDD platters may contain residual magnetic domains in "
            "reallocated sectors, grown defect lists (G-List), and servo tracks "
            "that are inaccessible to software-based overwrite. DEGAUSS neutralizes "
            "all magnetic domains regardless of logical accessibility."
        ),
        "verification": [
            VerificationRequirement.VISUAL_INSPECTION,
            VerificationRequirement.PHOTOGRAPHIC_RECORD,
            VerificationRequirement.CERTIFICATE_OF_DESTRUCTION,
        ],
        "special_notes": [
            "For SEDs (Self-Encrypting Drives): Crypto Erase via PSID revert "
            "may qualify as PURGE if the AES key is confirmed destroyed.",
            "Degausser must meet NSA/CSS EPL specifications for the coercivity "
            "of the target media (perpendicular recording: ≥7000 Oe).",
        ],
    },
    MediaType.SATA_SSD: {
        "primary_method": DestructionMethod.DISINTEGRATE,
        "secondary_methods": [DestructionMethod.PULVERIZE, DestructionMethod.INCINERATE],
        "reason_destroy_required": (
            "NAND flash SSDs maintain inaccessible spare area blocks, wear-leveling "
            "remapped pages, and over-provisioned capacity that software overwrite "
            "cannot address. ATA Secure Erase may not clear all NAND pages on all "
            "controllers. Physical destruction is the only NIST DESTROY-compliant "
            "option when firmware-level purge cannot be verified."
        ),
        "verification": [
            VerificationRequirement.PARTICLE_SIZE_CHECK,
            VerificationRequirement.WEIGHT_COMPARISON,
            VerificationRequirement.PHOTOGRAPHIC_RECORD,
            VerificationRequirement.CERTIFICATE_OF_DESTRUCTION,
        ],
        "special_notes": [
            "DEGAUSS is NOT effective on flash/SSD media (no magnetic domains).",
            "Particle size after disintegration must be ≤2mm per NIST guidance.",
            "NAND die-level recovery from intact chips is feasible with electron "
            "microscopy — ensure physical destruction of the NAND packages.",
        ],
    },
    MediaType.NVME_SSD: {
        "primary_method": DestructionMethod.DISINTEGRATE,
        "secondary_methods": [DestructionMethod.PULVERIZE, DestructionMethod.INCINERATE],
        "reason_destroy_required": (
            "NVMe SSDs with inaccessible namespaces, persistent memory regions (PMR), "
            "or controller-managed spare areas may retain data after NVMe Sanitize. "
            "If the controller does not support Crypto Erase or Block Erase sanitize "
            "commands, physical destruction is required."
        ),
        "verification": [
            VerificationRequirement.PARTICLE_SIZE_CHECK,
            VerificationRequirement.PHOTOGRAPHIC_RECORD,
            VerificationRequirement.CERTIFICATE_OF_DESTRUCTION,
        ],
        "special_notes": [
            "NVMe Sanitize (Block Erase or Crypto Erase) may qualify as PURGE "
            "if the controller reports sanitize completion via SANITIZE STATUS log page.",
            "If Sanitize is unsupported (check `nvme id-ctrl -H`), DESTROY is mandatory.",
        ],
    },
    MediaType.USB_FLASH: {
        "primary_method": DestructionMethod.DISINTEGRATE,
        "secondary_methods": [DestructionMethod.INCINERATE, DestructionMethod.PULVERIZE],
        "reason_destroy_required": (
            "USB flash drives use consumer-grade NAND with no standardized "
            "secure erase command. Wear leveling and bad block management are "
            "controller-proprietary and inaccessible. Software overwrite cannot "
            "guarantee all flash pages are addressed."
        ),
        "verification": [
            VerificationRequirement.VISUAL_INSPECTION,
            VerificationRequirement.PHOTOGRAPHIC_RECORD,
            VerificationRequirement.CERTIFICATE_OF_DESTRUCTION,
        ],
        "special_notes": [
            "Monolithic USB drives (chip-on-board) require specialized "
            "disintegration equipment — standard shredders may leave intact NAND die.",
        ],
    },
    MediaType.SD_CARD: {
        "primary_method": DestructionMethod.DISINTEGRATE,
        "secondary_methods": [DestructionMethod.INCINERATE],
        "reason_destroy_required": (
            "SD/microSD cards have no standardized secure erase interface. "
            "The SD specification's ERASE command only marks blocks for garbage "
            "collection — it does not guarantee data destruction. Physical "
            "destruction is the only reliable DESTROY method."
        ),
        "verification": [
            VerificationRequirement.VISUAL_INSPECTION,
            VerificationRequirement.PHOTOGRAPHIC_RECORD,
            VerificationRequirement.CERTIFICATE_OF_DESTRUCTION,
        ],
        "special_notes": [
            "microSD cards are small enough to be lost — maintain physical "
            "chain-of-custody from seizure through destruction.",
        ],
    },
    MediaType.VIRTUAL_DISK_IMAGE: {
        "primary_method": DestructionMethod.SHRED,
        "secondary_methods": [DestructionMethod.DISINTEGRATE],
        "reason_destroy_required": (
            "Virtual disk image files reside on a host filesystem. Software "
            "CLEAR (overwrite) of the image file is sufficient for the logical "
            "content, but the host physical media may retain remnants in "
            "filesystem journal, VSS snapshots, or SSD spare areas. If the "
            "host media requires DESTROY-level assurance, apply physical "
            "destruction to the host storage device."
        ),
        "verification": [
            VerificationRequirement.CERTIFICATE_OF_DESTRUCTION,
        ],
        "special_notes": [
            "For image files: CLEAR (overwrite) + secure deletion of the host "
            "file is typically sufficient. DESTROY of the host device is only "
            "required if the data classification mandates it.",
            "Consider NTFS journal ($LogFile, $UsnJrnl) and Volume Shadow "
            "Copies that may retain pre-overwrite data fragments.",
        ],
    },
    MediaType.UNKNOWN: {
        "primary_method": DestructionMethod.DISINTEGRATE,
        "secondary_methods": [DestructionMethod.INCINERATE, DestructionMethod.PULVERIZE],
        "reason_destroy_required": (
            "Media type could not be positively identified. When media type "
            "is unknown, NIST SP 800-88 Rev. 2 recommends defaulting to the "
            "most conservative sanitization level: DESTROY."
        ),
        "verification": [
            VerificationRequirement.VISUAL_INSPECTION,
            VerificationRequirement.PARTICLE_SIZE_CHECK,
            VerificationRequirement.PHOTOGRAPHIC_RECORD,
            VerificationRequirement.CERTIFICATE_OF_DESTRUCTION,
        ],
        "special_notes": [
            "Identify the media type before destruction if possible — it "
            "determines which destruction methods are effective.",
        ],
    },
}


@dataclass
class WitnessRecord:
    """Attestation by an authorized witness to the destruction event."""
    witness_name: str
    witness_id: str
    role: str                    # e.g., "Investigating Officer", "Lab Supervisor"
    organization: str
    timestamp: Optional[str] = None  # ISO 8601; filled at manifest generation

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DisposalManifestEntry:
    """A single media item in the disposal manifest."""
    item_id: str                         # Unique tracking ID for this item
    serial_number: Optional[str]         # Drive serial number (if known)
    make_model: Optional[str]            # Manufacturer and model
    capacity: Optional[str]              # e.g., "500 GB", "32 GB"
    media_capability: Dict[str, Any]     # DeviceCapability.to_dict() output
    destruction_method: str              # DestructionMethod.value
    destruction_method_description: str
    alternative_methods: List[str]
    reason_destroy_required: str
    verification_requirements: List[str]
    special_notes: List[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PhysicalDisposalManifest:
    """
    NIST SP 800-88 Rev. 2 compliant physical disposal manifest.
    
    This document accompanies the physical destruction of storage media
    and serves as the official chain-of-custody handoff record.
    """
    manifest_id: str
    case_id: str
    generated_at: str                    # ISO 8601
    generated_by: str                    # System identifier
    nist_reference: str
    classification_level: str            # "CONFIDENTIAL", "SECRET", etc.
    items: List[Dict[str, Any]]
    operator: Dict[str, Any]             # Who authorized the destruction
    witnesses: List[Dict[str, Any]]
    chain_of_custody: List[Dict[str, Any]]
    pre_destruction_checklist: List[Dict[str, Any]]
    post_destruction_verification: List[Dict[str, Any]]
    legal_citations: List[str]
    manifest_hash: str                   # SHA-256 of manifest content (self-integrity)
    scope_statement: str
    disclaimer: str

    def to_dict(self) -> dict:
        return asdict(self)


# ── Pre-destruction checklist items ─────────────────────────────────────────

PRE_DESTRUCTION_CHECKLIST = [
    {
        "step": 1,
        "requirement": "Confirm all forensic acquisitions are complete",
        "description": (
            "Verify that all required forensic images, extractions, and analyses "
            "have been completed and verified before authorizing destruction."
        ),
        "completed": False,
    },
    {
        "step": 2,
        "requirement": "Verify case disposition authorizes destruction",
        "description": (
            "Confirm that the case officer, court order, or organizational policy "
            "authorizes the destruction of this evidence media."
        ),
        "completed": False,
    },
    {
        "step": 3,
        "requirement": "Record all serial numbers and identifying marks",
        "description": (
            "Document serial numbers, asset tags, barcodes, and physical "
            "identifying marks of each media item before destruction."
        ),
        "completed": False,
    },
    {
        "step": 4,
        "requirement": "Photograph media items pre-destruction",
        "description": (
            "Take clear photographs of each media item with serial numbers "
            "visible, timestamp-stamped, alongside the case reference card."
        ),
        "completed": False,
    },
    {
        "step": 5,
        "requirement": "Verify destruction equipment certification",
        "description": (
            "Confirm the degausser, shredder, or incinerator is certified "
            "for the media type and meets the required specifications."
        ),
        "completed": False,
    },
    {
        "step": 6,
        "requirement": "Two authorized witnesses present",
        "description": (
            "At least two authorized personnel must witness the physical "
            "destruction. One must be the case officer or their delegate."
        ),
        "completed": False,
    },
]


def generate_disposal_manifest(
    case_id: str,
    target_path: str,
    operator_id: str,
    operator_name: str,
    authorization_reason: str,
    serial_number: Optional[str] = None,
    make_model: Optional[str] = None,
    capacity: Optional[str] = None,
    classification_level: str = "CONFIDENTIAL",
    witnesses: Optional[List[Dict[str, str]]] = None,
) -> PhysicalDisposalManifest:
    """
    Generate a NIST SP 800-88 Rev. 2 DESTROY-branch physical disposal manifest.

    This produces a structured document that must accompany the physical
    destruction of storage media when software-based Clear/Purge is
    insufficient or unavailable.

    Args:
        case_id: The forensic case identifier.
        target_path: Path to the media or image file being disposed.
        operator_id: ID of the operator authorizing destruction.
        operator_name: Name of the operator.
        authorization_reason: Why destruction is authorized.
        serial_number: Drive serial number (if known).
        make_model: Manufacturer and model (if known).
        capacity: Storage capacity string (if known).
        classification_level: Data classification level.
        witnesses: List of witness records [{"name": ..., "id": ..., "role": ..., "org": ...}].

    Returns:
        PhysicalDisposalManifest with all required documentation fields.
    """
    manifest_id = f"DESTROY-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc).isoformat()

    # Detect media type and capability
    capability = detect_media_type(target_path)
    media_type = capability.media_type

    # Look up destruction matrix for this media type
    matrix = DESTRUCTION_MATRIX.get(media_type, DESTRUCTION_MATRIX[MediaType.UNKNOWN])

    # Build item entry
    item = DisposalManifestEntry(
        item_id=f"ITEM-{uuid.uuid4().hex[:8].upper()}",
        serial_number=serial_number,
        make_model=make_model,
        capacity=capacity,
        media_capability=capability.to_dict(),
        destruction_method=matrix["primary_method"].value,
        destruction_method_description=matrix["primary_method"].description,
        alternative_methods=[m.value for m in matrix["secondary_methods"]],
        reason_destroy_required=matrix["reason_destroy_required"],
        verification_requirements=[v.value for v in matrix["verification"]],
        special_notes=matrix["special_notes"],
    )

    # Build witness records
    witness_records = []
    if witnesses:
        for w in witnesses:
            wr = WitnessRecord(
                witness_name=w.get("name", ""),
                witness_id=w.get("id", ""),
                role=w.get("role", ""),
                organization=w.get("org", w.get("organization", "")),
                timestamp=now,
            )
            witness_records.append(wr.to_dict())

    # Chain of custody handoff record
    chain_of_custody = [
        {
            "event": "MANIFEST_GENERATED",
            "timestamp": now,
            "actor": operator_name,
            "actor_id": operator_id,
            "description": f"Physical disposal manifest generated for case {case_id}",
        },
        {
            "event": "PENDING_DESTRUCTION",
            "timestamp": None,
            "actor": None,
            "actor_id": None,
            "description": (
                "Media item transferred to authorized destruction facility. "
                "To be filled by the receiving party."
            ),
        },
        {
            "event": "DESTRUCTION_COMPLETED",
            "timestamp": None,
            "actor": None,
            "actor_id": None,
            "description": (
                "Physical destruction completed and verified. "
                "To be filled by the destruction operator and witnesses."
            ),
        },
    ]

    # Post-destruction verification
    post_verification = [
        {
            "check": v.value,
            "description": _verification_description(v),
            "completed": False,
            "completed_by": None,
            "completed_at": None,
        }
        for v in matrix["verification"]
    ]

    # Legal citations (verified, real citations only)
    legal_citations = [
        "NIST SP 800-88 Rev. 2 — Guidelines for Media Sanitization (September 2025)",
        "NIST SP 800-88 Rev. 2 §2.5 — Destroy: Physical destruction methods",
        "IEEE 2883-2022 — Standard for Sanitizing Storage",
        "Bharatiya Sakshya Adhiniyam 2023 §63(4) — Admissibility of electronic evidence",
        "IT Act 2000 §65B — Admissibility of electronic records",
    ]

    # Build manifest (without hash first, then compute)
    manifest_content = {
        "manifest_id": manifest_id,
        "case_id": case_id,
        "generated_at": now,
        "items": [item.to_dict()],
        "operator": {
            "id": operator_id,
            "name": operator_name,
            "authorization_reason": authorization_reason,
        },
        "classification_level": classification_level,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_content, sort_keys=True).encode()
    ).hexdigest()

    return PhysicalDisposalManifest(
        manifest_id=manifest_id,
        case_id=case_id,
        generated_at=now,
        generated_by="SIH26149 — Forensic Evidence Workstation",
        nist_reference="NIST SP 800-88 Rev. 2 §2.5 Destroy",
        classification_level=classification_level,
        items=[item.to_dict()],
        operator={
            "id": operator_id,
            "name": operator_name,
            "authorization_reason": authorization_reason,
        },
        witnesses=witness_records,
        chain_of_custody=chain_of_custody,
        pre_destruction_checklist=[dict(c) for c in PRE_DESTRUCTION_CHECKLIST],
        post_destruction_verification=post_verification,
        legal_citations=legal_citations,
        manifest_hash=manifest_hash,
        scope_statement=(
            "This manifest documents the DESTROY-level sanitization requirement "
            "for media that cannot be adequately sanitized via software-based "
            "CLEAR or PURGE methods. The physical destruction must be performed "
            "by authorized personnel at a certified facility. This document "
            "constitutes the chain-of-custody handoff record and must be retained "
            "as part of the case file."
        ),
        disclaimer=(
            "This manifest is generated by an automated system. The destruction "
            "methods recommended are based on NIST SP 800-88 Rev. 2 guidelines "
            "and the detected media type. Actual destruction must be performed "
            "by qualified personnel using certified equipment. This system does "
            "not perform physical destruction — it generates documentation only."
        ),
    )


def _verification_description(req: VerificationRequirement) -> str:
    """Human-readable description for each verification requirement."""
    return {
        VerificationRequirement.VISUAL_INSPECTION: (
            "Visually confirm media is destroyed beyond recognition. "
            "No intact platters, chips, or substrates should be identifiable."
        ),
        VerificationRequirement.PARTICLE_SIZE_CHECK: (
            "Measure particle size of shredded/disintegrated output. "
            "All particles must be ≤2mm in any dimension per NIST guidance."
        ),
        VerificationRequirement.WEIGHT_COMPARISON: (
            "Compare pre-destruction and post-destruction weight to confirm "
            "all media material is accounted for (no pieces diverted)."
        ),
        VerificationRequirement.PHOTOGRAPHIC_RECORD: (
            "Photograph the destroyed media output with a timestamp card "
            "and case reference visible. Photos become part of the case file."
        ),
        VerificationRequirement.CERTIFICATE_OF_DESTRUCTION: (
            "Obtain a signed Certificate of Destruction from the destruction "
            "facility operator, including date, method, equipment ID, and "
            "witness signatures."
        ),
    }[req]


def generate_manifest_html(manifest: PhysicalDisposalManifest) -> str:
    """
    Render the disposal manifest as a printable HTML document.
    
    Designed for court submission and physical records — includes
    signature blocks, witness lines, and checklist checkboxes.
    """
    items_html = ""
    for item in manifest.items:
        items_html += f"""
        <div class="manifest-item">
            <h3>Item: {item['item_id']}</h3>
            <table class="item-table">
                <tr><td class="label">Serial Number</td><td>{item.get('serial_number') or 'Not recorded'}</td></tr>
                <tr><td class="label">Make / Model</td><td>{item.get('make_model') or 'Not recorded'}</td></tr>
                <tr><td class="label">Capacity</td><td>{item.get('capacity') or 'Not recorded'}</td></tr>
                <tr><td class="label">Media Type</td><td>{item['media_capability']['media_type']}</td></tr>
                <tr><td class="label">Recommended Level</td><td>{item['media_capability']['recommended_level']}</td></tr>
                <tr><td class="label">Destruction Method</td><td><strong>{item['destruction_method']}</strong> — {item['destruction_method_description']}</td></tr>
                <tr><td class="label">Alternative Methods</td><td>{', '.join(item['alternative_methods'])}</td></tr>
            </table>
            <div class="reason-block">
                <h4>Reason DESTROY Required</h4>
                <p>{item['reason_destroy_required']}</p>
            </div>
            <div class="notes-block">
                <h4>Special Notes</h4>
                <ul>{''.join(f'<li>{n}</li>' for n in item['special_notes'])}</ul>
            </div>
        </div>
        """

    checklist_html = ""
    for c in manifest.pre_destruction_checklist:
        checklist_html += f"""
        <tr>
            <td class="step-num">{c['step']}</td>
            <td>{c['requirement']}</td>
            <td class="desc">{c['description']}</td>
            <td class="checkbox">☐</td>
            <td class="sign-line">______________</td>
        </tr>
        """

    verification_html = ""
    for v in manifest.post_destruction_verification:
        verification_html += f"""
        <tr>
            <td>{v['check']}</td>
            <td class="desc">{v['description']}</td>
            <td class="checkbox">☐</td>
            <td class="sign-line">______________</td>
            <td class="sign-line">______________</td>
        </tr>
        """

    witness_html = ""
    if manifest.witnesses:
        for w in manifest.witnesses:
            witness_html += f"""
            <tr>
                <td>{w.get('witness_name', '')}</td>
                <td>{w.get('witness_id', '')}</td>
                <td>{w.get('role', '')}</td>
                <td>{w.get('organization', '')}</td>
                <td class="sign-line">______________</td>
            </tr>
            """
    else:
        witness_html = """
        <tr><td colspan="5" style="text-align:center; color:#666;">
            Witness records to be added at time of destruction
        </td></tr>
        """

    coc_html = ""
    for event in manifest.chain_of_custody:
        ts = event.get('timestamp') or '________________'
        actor = event.get('actor') or '________________'
        coc_html += f"""
        <tr>
            <td><strong>{event['event']}</strong></td>
            <td>{ts}</td>
            <td>{actor}</td>
            <td class="desc">{event['description']}</td>
            <td class="sign-line">______________</td>
        </tr>
        """

    citations_html = "".join(f"<li>{c}</li>" for c in manifest.legal_citations)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Physical Disposal Manifest — {manifest.manifest_id}</title>
<style>
    @page {{ margin: 2cm; }}
    body {{
        font-family: 'Times New Roman', Georgia, serif;
        font-size: 11pt;
        line-height: 1.4;
        color: #111;
        max-width: 800px;
        margin: 0 auto;
        padding: 20px;
    }}
    .header {{
        text-align: center;
        border-bottom: 3px double #333;
        padding-bottom: 15px;
        margin-bottom: 20px;
    }}
    .header h1 {{
        font-size: 16pt;
        margin: 0;
        letter-spacing: 2px;
        text-transform: uppercase;
    }}
    .header h2 {{
        font-size: 12pt;
        margin: 5px 0;
        color: #444;
        font-weight: normal;
    }}
    .classification {{
        display: inline-block;
        border: 2px solid #c00;
        color: #c00;
        padding: 2px 12px;
        font-weight: bold;
        letter-spacing: 3px;
        margin: 10px 0;
    }}
    .meta-table {{
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
    }}
    .meta-table td {{
        padding: 4px 8px;
        border: 1px solid #ccc;
        font-size: 10pt;
    }}
    .meta-table .label {{
        font-weight: bold;
        width: 180px;
        background: #f5f5f5;
    }}
    h3 {{
        border-bottom: 1px solid #999;
        padding-bottom: 3px;
        margin-top: 25px;
    }}
    .manifest-item {{
        border: 1px solid #999;
        padding: 15px;
        margin: 15px 0;
        background: #fafafa;
    }}
    .item-table {{
        width: 100%;
        border-collapse: collapse;
    }}
    .item-table td {{
        padding: 4px 8px;
        border: 1px solid #ddd;
        font-size: 10pt;
    }}
    .item-table .label {{
        font-weight: bold;
        width: 180px;
        background: #f0f0f0;
    }}
    .reason-block, .notes-block {{
        margin-top: 10px;
        padding: 8px;
        background: #fff;
        border-left: 3px solid #c00;
    }}
    .reason-block h4, .notes-block h4 {{
        margin: 0 0 5px 0;
        font-size: 10pt;
    }}
    table.checklist, table.verification, table.witness, table.coc {{
        width: 100%;
        border-collapse: collapse;
        margin: 10px 0;
        font-size: 10pt;
    }}
    table.checklist th, table.verification th, table.witness th, table.coc th {{
        background: #333;
        color: #fff;
        padding: 6px 8px;
        text-align: left;
    }}
    table.checklist td, table.verification td, table.witness td, table.coc td {{
        padding: 6px 8px;
        border: 1px solid #ccc;
        vertical-align: top;
    }}
    .step-num {{
        width: 30px;
        text-align: center;
        font-weight: bold;
    }}
    .checkbox {{
        width: 30px;
        text-align: center;
        font-size: 14pt;
    }}
    .sign-line {{
        width: 100px;
        text-align: center;
        color: #999;
    }}
    .desc {{
        font-size: 9pt;
        color: #555;
    }}
    .signature-block {{
        margin-top: 30px;
        display: flex;
        justify-content: space-between;
    }}
    .sig-box {{
        width: 45%;
        border-top: 1px solid #333;
        padding-top: 5px;
        text-align: center;
        font-size: 10pt;
    }}
    .footer {{
        margin-top: 30px;
        padding-top: 10px;
        border-top: 3px double #333;
        font-size: 9pt;
        color: #666;
        text-align: center;
    }}
    .hash-block {{
        font-family: 'Courier New', monospace;
        font-size: 9pt;
        background: #f5f5f5;
        padding: 5px;
        word-break: break-all;
        border: 1px solid #ddd;
        margin: 10px 0;
    }}
    @media print {{
        body {{ padding: 0; }}
        .no-print {{ display: none; }}
    }}
</style>
</head>
<body>

<div class="header">
    <h1>Physical Disposal Manifest</h1>
    <h2>NIST SP 800-88 Rev. 2 — DESTROY Branch</h2>
    <div class="classification">{manifest.classification_level}</div>
</div>

<table class="meta-table">
    <tr><td class="label">Manifest ID</td><td>{manifest.manifest_id}</td></tr>
    <tr><td class="label">Case ID</td><td>{manifest.case_id}</td></tr>
    <tr><td class="label">Generated</td><td>{manifest.generated_at}</td></tr>
    <tr><td class="label">Generated By</td><td>{manifest.generated_by}</td></tr>
    <tr><td class="label">NIST Reference</td><td>{manifest.nist_reference}</td></tr>
    <tr><td class="label">Authorized By</td><td>{manifest.operator['name']} ({manifest.operator['id']})</td></tr>
    <tr><td class="label">Reason</td><td>{manifest.operator['authorization_reason']}</td></tr>
</table>

<h3>1. Media Items for Destruction</h3>
{items_html}

<h3>2. Pre-Destruction Checklist</h3>
<table class="checklist">
    <thead>
        <tr><th>#</th><th>Requirement</th><th>Description</th><th>✓</th><th>Initials</th></tr>
    </thead>
    <tbody>
        {checklist_html}
    </tbody>
</table>

<h3>3. Post-Destruction Verification</h3>
<table class="verification">
    <thead>
        <tr><th>Check</th><th>Description</th><th>✓</th><th>Verified By</th><th>Date</th></tr>
    </thead>
    <tbody>
        {verification_html}
    </tbody>
</table>

<h3>4. Witness Attestation</h3>
<table class="witness">
    <thead>
        <tr><th>Name</th><th>ID</th><th>Role</th><th>Organization</th><th>Signature</th></tr>
    </thead>
    <tbody>
        {witness_html}
    </tbody>
</table>

<h3>5. Chain of Custody</h3>
<table class="coc">
    <thead>
        <tr><th>Event</th><th>Timestamp</th><th>Actor</th><th>Description</th><th>Signature</th></tr>
    </thead>
    <tbody>
        {coc_html}
    </tbody>
</table>

<h3>6. Legal Citations</h3>
<ul>{citations_html}</ul>

<h3>7. Scope Statement</h3>
<p>{manifest.scope_statement}</p>

<h3>8. Disclaimer</h3>
<p style="font-size:9pt; color:#666;">{manifest.disclaimer}</p>

<h3>9. Manifest Integrity</h3>
<div class="hash-block">
    SHA-256: {manifest.manifest_hash}
</div>

<div class="signature-block">
    <div class="sig-box">
        Authorizing Officer<br>
        <br><br>
        Name: _________________________<br>
        Date: _________________________
    </div>
    <div class="sig-box">
        Destruction Facility Operator<br>
        <br><br>
        Name: _________________________<br>
        Date: _________________________
    </div>
</div>

<div class="footer">
    <p>SIH26149 — Forensic Evidence Workstation | Physical Disposal Manifest v1.0</p>
    <p>This document must be retained as part of the case file per BSA 2023 §63(4).</p>
</div>

</body>
</html>"""
