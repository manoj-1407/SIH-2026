"""Generate technical reliability summaries without asserting legal compliance."""
import json
import hashlib
from html import escape
from typing import Dict, Any, Optional
from datetime import datetime, timezone

TOTAL_VERIFIED_TESTS: Optional[int] = None


def generate_reliability_statement(
    examiner_name: str = "Not specified",
    lab_organization: str = "Not specified",
    case_id: Optional[str] = None
) -> Dict[str, Any]:
    """Return a technical status summary; no tests are run and no legal opinion is made."""
    now_utc = datetime.now(timezone.utc).isoformat()
    report_id = f"RELIABILITY-REPORT-{hashlib.sha256(now_utc.encode()).hexdigest()[:12].upper()}"
    statement: Dict[str, Any] = {
        "report_id": report_id,
        "generated_at_utc": now_utc,
        "applicable_legal_frameworks": [
            "Bharatiya Sakshya Adhiniyam (BSA) 2023 §39 (expert opinions) and §63 (certificate requirements): references only; compliance is not assessed.",
            "US Federal Rule of Evidence 702 / Daubert: US legal framework, not an Indian admissibility determination.",
            "ISO/IEC 27037:2012 and NIST SP 800-88 Rev. 2: technical references; conformance is not assessed here."
        ],
        "system_provenance": {
            "organization": lab_organization or "Not specified",
            "examiner": examiner_name or "Not specified",
            "associated_case_id": case_id or "Not specified"
        },
        "empirical_reliability_metrics": {
            "total_adversarial_test_vectors": None,
            "confirmed_test_failures": None,
            "empirical_error_rate_percentage": "NOT MEASURED",
            "statistical_confidence_interval": "NOT CALCULATED",
            "false_positive_rate": "NOT MEASURED",
            "tests_executed_by_this_report": False,
            "categories": {}
        },
        "technical_and_legal_boundaries": [
            {
                "standard": "Test execution and empirical error rate",
                "finding": "NOT MEASURED",
                "evidence": "Generating this report does not execute or collect tests; no error rate is inferred."
            },
            {
                "standard": "Cryptographic controls",
                "finding": "IMPLEMENTATION CLAIM ONLY",
                "evidence": "The project implements Ed25519, canonicalization, and hash-chain checks; this report does not establish legal sufficiency."
            },
            {
                "standard": "BSA 2023 §63(4) certificate requirements",
                "finding": "NOT ASSESSED",
                "evidence": "This software-generated summary is not a statutory certificate, affidavit, or admissibility determination."
            }
        ],
        "not_a_legal_opinion_or_certificate": True
    }

    payload_str = json.dumps(statement, sort_keys=True, separators=(",", ":"))
    statement["report_integrity_sha256"] = hashlib.sha256(payload_str.encode()).hexdigest()

    return statement


def generate_reliability_statement_html(statement: Dict[str, Any]) -> str:
    """Render the technical reliability summary with escaped report fields."""
    metrics = statement["empirical_reliability_metrics"]
    boundaries = statement["technical_and_legal_boundaries"]
    sys_meta = statement["system_provenance"]
    legal_reference_items = "".join(
        f"<li>{escape(str(reference))}</li>"
        for reference in statement["applicable_legal_frameworks"]
    )

    boundary_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(str(item["standard"])),
            escape(str(item["finding"])),
            escape(str(item["evidence"])),
        )
        for item in boundaries
    )
    safe = lambda value: escape(str(value))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Technical Reliability Summary — {safe(statement['report_id'])}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0a0e17; color: #e2e8f0; line-height: 1.5; padding: 2rem; margin: 0; }}
    .container {{ max-width: 900px; margin: auto; background: #111827; border: 1px solid #1f293d; border-radius: 8px; padding: 2.5rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
    .header {{ border-bottom: 2px solid #00e5ff; padding-bottom: 1.2rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: flex-start; }}
    .title {{ font-size: 1.6rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; }}
    .subtitle {{ font-size: 0.85rem; color: #00e5ff; font-weight: 600; text-transform: uppercase; margin-top: 4px; }}
    .badge {{ background: #00e5ff15; border: 1px solid #00e5ff40; color: #00e5ff; padding: 4px 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; font-weight: 600; }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }}
    .card {{ background: #162032; border: 1px solid #233148; border-radius: 6px; padding: 1rem; }}
    .card-title {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700; margin-bottom: 4px; }}
    .card-val {{ font-size: 1.2rem; color: #fff; font-weight: 700; font-family: monospace; }}
    .card-val.green {{ color: #00e676; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; margin-bottom: 2rem; font-size: 0.85rem; }}
    th, td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid #222f44; text-align: left; }}
    th {{ background: #162032; color: #94a3b8; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.05em; }}
    .footer {{ margin-top: 2rem; border-top: 1px solid #222f44; padding-top: 1rem; font-size: 0.75rem; color: #64748b; font-family: monospace; }}
    @media print {{ body {{ background: #fff; color: #000; padding: 0; }} .container {{ border: none; box-shadow: none; padding: 1rem; }} }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="title">TECHNICAL RELIABILITY SUMMARY</div>
        <div class="subtitle">Measured implementation status only · legal compliance and admissibility not assessed</div>
      </div>
      <div class="badge">{safe(statement['report_id'])}</div>
    </div>

    <p><strong>Important:</strong> This generated summary is not an affidavit, statutory certificate, legal opinion, or determination of admissibility. Review applicable BSA requirements with qualified counsel and the responsible certifying person.</p>
    <h3 style="font-size:1.05rem;color:#fff;">Legal and technical references (not compliance findings)</h3>
    <ul>{legal_reference_items}</ul>
    <div class="grid-2">
      <div class="card">
        <div class="card-title">Organization / examiner supplied</div>
        <div class="card-val">{safe(sys_meta['organization'])}</div>
        <div style="font-size:0.8rem;color:#94a3b8;margin-top:4px;">Examiner: {safe(sys_meta['examiner'])}</div>
      </div>
      <div class="card">
        <div class="card-title">Empirical error rate</div>
        <div class="card-val">{safe(metrics['empirical_error_rate_percentage'])}</div>
        <div style="font-size:0.8rem;color:#94a3b8;margin-top:4px;">Tests executed by this report: No</div>
      </div>
    </div>

    <h3 style="font-size:1.05rem;color:#fff;margin-top:1.5rem;">Technical and legal boundaries</h3>
    <table>
      <thead><tr><th>Area</th><th>Finding</th><th>Evidence / limitation</th></tr></thead>
      <tbody>{boundary_rows}</tbody>
    </table>

    <div class="footer">
      <div>REPORT SHA-256: {safe(statement['report_integrity_sha256'])}</div>
      <div style="margin-top:4px;">GENERATED UTC: {safe(statement['generated_at_utc'])} · CASE: {safe(sys_meta['associated_case_id'])}</div>
    </div>
  </div>
</body>
</html>"""


def generate_artifact_admissibility_paragraph(
    artifact_dict: Dict[str, Any],
    case_dict: Dict[str, Any],
    examiner_dict: Dict[str, Any],
) -> str:
    """Generate a cautious legal-reference note for a recovered artifact.

    This is an operational record aid, not a legal opinion or statutory certificate.
    """
    artifact_name = artifact_dict.get('name') or artifact_dict.get('artifact_name') or artifact_dict.get('filename') or 'artifact'
    sha = artifact_dict.get('sha256') or artifact_dict.get('recovered_sha256') or 'N/A'
    size = artifact_dict.get('size_bytes') or artifact_dict.get('size') or 0
    method = artifact_dict.get('recovery_method') or artifact_dict.get('method') or 'FORENSIC_RECOVERY'
    confidence = artifact_dict.get('confidence') or 'UNCLASSIFIED'
    case_ref = case_dict.get('title') or case_dict.get('case_ref') or ''
    case_id = case_dict.get('case_id') or 'UNKNOWN-CASE'
    examiner_name = examiner_dict.get('name') or examiner_dict.get('examiner_name') or 'Not specified'
    examiner_id = examiner_dict.get('id') or examiner_dict.get('examiner_id') or 'Not specified'
    timestamp = datetime.now(timezone.utc).isoformat()

    source_pre = artifact_dict.get('source_sha256_pre')
    source_post = artifact_dict.get('source_sha256_post')
    source_integrity = (
        f'Recorded source hashes: pre={source_pre}, post={source_post}; '
        f'match={str(source_pre == source_post).lower()}.'
        if source_pre and source_post
        else 'Source pre/post hash comparison was not supplied in this artifact record.'
    )
    audit_event_id = artifact_dict.get('audit_event_id') or artifact_dict.get('last_event_id')
    audit_note = (
        f'Referenced audit event ID: {audit_event_id}.'
        if audit_event_id
        else 'No audit event ID was supplied in this artifact record.'
    )
    confidence_note = (
        'HEADER_ONLY indicates that only a file header was recovered; payload '
        'integrity and completeness are not established.'
        if str(confidence).upper() == 'HEADER_ONLY'
        else f'Recorded recovery confidence: {confidence}; this label does not independently establish completeness.'
    )

    return ' '.join((
        f'Operational artifact record generated at {timestamp} UTC for "{artifact_name}" '
        f'(case ID {case_id}; reference "{case_ref}"; size {size} bytes; SHA-256 {sha}).',
        f'The recorded recovery method is {method}, and the recorded examiner is '
        f'{examiner_name} (ID: {examiner_id}); no examiner credential is asserted by this software.',
        confidence_note,
        source_integrity,
        audit_note,
        'BSA 2023, §39 concerns expert opinions under the Bharatiya Sakshya Adhiniyam; '
        'this software-generated note is not itself an expert opinion.',
        'BSA 2023, §63(4) concerns requirements for a certificate accompanying '
        'specified electronic records; this note does not satisfy or replace that certificate.',
        'Section 65B was in the Indian Evidence Act, 1872, not the Information '
        'Technology Act; current and transitional applicability must be determined by qualified counsel.',
        'This note is a technical record aid only, not a legal opinion, affidavit, '
        'certification, or determination of admissibility.',
    ))


def generate_sanitization_admissibility_paragraph(
    sanitization_dict: Dict[str, Any],
    case_dict: Dict[str, Any],
    examiner_dict: Dict[str, Any],
) -> str:
    """Generate a cautious legal-reference note for a sanitization result."""
    method = sanitization_dict.get('method') or sanitization_dict.get('sanitization_method') or 'ZERO_FILL'
    source_sha = (
        sanitization_dict.get('pre_operation_sha256')
        or sanitization_dict.get('source_sha256')
        or sanitization_dict.get('source_sha')
        or sanitization_dict.get('input_sha256')
        or 'N/A'
    )
    ieee_ref = sanitization_dict.get('ieee_2883_reference') or None
    nist_section = sanitization_dict.get('nist_sp800_88_section') or 'not specified'
    case_ref = case_dict.get('title') or case_dict.get('case_ref') or ''
    case_id = case_dict.get('case_id') or 'UNKNOWN-CASE'
    examiner_name = examiner_dict.get('name') or examiner_dict.get('examiner_name') or 'Not specified'
    examiner_id = examiner_dict.get('id') or examiner_dict.get('examiner_id') or 'Not specified'
    timestamp = datetime.now(timezone.utc).isoformat()
    classification = sanitization_dict.get('classification') or sanitization_dict.get('result_classification') or 'NOT_REPORTED'
    execution_status = sanitization_dict.get('execution_status') or sanitization_dict.get('status') or 'not supplied'
    verification_details = sanitization_dict.get('verification_details') or {}
    bytes_zeroed = verification_details.get('bytes_verified_zero')
    if bytes_zeroed is not None:
        readback_note = f'Read-back verification reported {bytes_zeroed} bytes containing zero.'
    elif verification_details.get('post_sha256'):
        readback_note = (
            'Read-back verification reported a post-operation SHA-256 of '
            f'{verification_details["post_sha256"]}; this is not a physical-media probe.'
        )
    else:
        readback_note = 'Read-back verification details were not supplied.'
    bytes_written = sanitization_dict.get('bytes_written')
    write_note = (
        f'The software reported writing {bytes_written} bytes.'
        if bytes_written is not None
        else 'The number of bytes written was not supplied.'
    )
    ieee_clause = f'IEEE 2883-2022 reference recorded: {ieee_ref}.' if ieee_ref else 'No IEEE 2883-2022 reference was supplied.'

    return ' '.join((
        f'Operational sanitization record generated at {timestamp} UTC for case {case_id} '
        f'("{case_ref}"): method={method}, NIST SP 800-88 Rev. 2 reference={nist_section}, '
        f'status={execution_status}, recorded classification={classification}.',
        write_note,
        readback_note,
        f'Pre-operation target SHA-256 recorded: {source_sha}; this value alone does not prove that sanitization succeeded.',
        ieee_clause,
        f'The recorded examiner is {examiner_name} (ID: {examiner_id}); no examiner credential is asserted by this software.',
        'BSA 2023, §63(4) concerns requirements for a certificate accompanying specified electronic records; this note does not satisfy or replace that certificate.',
        'Section 65B was in the Indian Evidence Act, 1872, not the Information Technology Act; current and transitional applicability must be determined by qualified counsel.',
        'This note is a technical record aid only, not a legal opinion, affidavit, certification, or determination of admissibility.',
    ))
