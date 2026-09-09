"""
Forensic Evidence Certificate Generator — SIH26149

Generates court-ready evidence certificates in HTML and PDF format.
Embeds a cryptographic QR code encoding the evidence envelope for
independent offline verification.

Outputs:
  - HTML certificate (self-contained, printable, embed-friendly)
  - QR code SVG/PNG encoding the evidence_hash for offline verification

No external dependencies required for HTML certificate.
PDF generation uses ReportLab if available (graceful fallback to HTML).
QR code uses qrcode library if available.
"""
import json
import hashlib
import datetime
from typing import Optional


_CSS = """
body { font-family: 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; margin: 0; padding: 0; background: #f4f4f8; }
.cert-page { max-width: 800px; margin: 40px auto; background: white; border: 2px solid #16213e;
             border-radius: 8px; padding: 48px 56px; box-shadow: 0 8px 32px rgba(0,0,0,0.15); }
.cert-header { text-align: center; border-bottom: 3px double #16213e; padding-bottom: 24px; margin-bottom: 32px; }
.cert-title  { font-size: 22px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #16213e; }
.cert-sub    { font-size: 12px; color: #666; margin-top: 8px; letter-spacing: 1px; }
.cert-seal   { font-size: 48px; margin: 12px 0; }
.section { margin-bottom: 28px; }
.section-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px;
                 color: #555; border-bottom: 1px solid #ddd; padding-bottom: 6px; margin-bottom: 14px; }
.kv-row  { display: flex; gap: 12px; padding: 6px 0; border-bottom: 1px solid #f0f0f4; font-size: 13px; }
.kv-k    { min-width: 200px; font-weight: 600; color: #444; }
.kv-v    { font-family: 'Courier New', monospace; color: #16213e; word-break: break-all; flex: 1; }
.classification { text-align: center; padding: 20px; margin: 24px 0;
                  border: 2px solid; border-radius: 6px; font-size: 16px; font-weight: 700; letter-spacing: 1px; }
.classification.VERIFIED       { border-color: #16a34a; color: #16a34a; background: #f0fdf4; }
.classification.VERIFIED_WITHIN_SCOPE { border-color: #ca8a04; color: #ca8a04; background: #fffbeb; }
.classification.UNVERIFIED     { border-color: #6b7280; color: #6b7280; background: #f9fafb; }
.classification.INVALID        { border-color: #dc2626; color: #dc2626; background: #fef2f2; }
.cert-footer { margin-top: 40px; padding-top: 20px; border-top: 2px double #16213e;
               font-size: 10.5px; color: #888; text-align: center; line-height: 1.8; }
.qr-box  { text-align: center; padding: 16px; background: #f8f8fc; border-radius: 6px; margin-top: 20px; }
.qr-label { font-size: 10px; color: #888; margin-top: 8px; font-family: 'Courier New', monospace; }
.sig-box { background: #f0f0f8; border-left: 4px solid #16213e; padding: 12px 16px; border-radius: 4px; margin-top: 16px; }
.sig-hash { font-family: 'Courier New', monospace; font-size: 11px; word-break: break-all; color: #16213e; }
"""


def _html_kv(rows: list) -> str:
    return ''.join(
        f'<div class="kv-row"><span class="kv-k">{k}</span><span class="kv-v">{v}</span></div>'
        for k, v in rows
    )


def generate_html_certificate(
    evidence_package: dict,
    case_title: Optional[str] = None,
) -> str:
    """
    Generate a self-contained HTML forensic evidence certificate.

    Args:
        evidence_package: Signed evidence envelope from evidence_store.
        case_title: Optional human-readable case title for the certificate.

    Returns:
        HTML string (self-contained, printable).
    """
    ev_id    = evidence_package.get('evidence_id', '—')
    case_id  = evidence_package.get('case_id', '—')
    ev_type  = evidence_package.get('evidence_type', '—')
    ev_hash  = evidence_package.get('evidence_hash', '—')
    key_id   = evidence_package.get('key_id', '—')
    signed_at = evidence_package.get('signed_at_utc', '')
    created_at = evidence_package.get('created_at_utc', '')
    result   = evidence_package.get('result', {})
    classification = result.get('classification', 'UNVERIFIED')
    explanation    = result.get('explanation', '—')
    scope          = evidence_package.get('scope', '—')
    algorithm      = evidence_package.get('signing_algorithm', 'Ed25519')
    signature_hex  = evidence_package.get('signature', '')

    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # QR code generation (graceful fallback)
    qr_html = ''
    try:
        import qrcode
        import qrcode.image.svg
        import io
        qr_data = json.dumps({
            'evidence_id': ev_id,
            'evidence_hash': ev_hash,
            'key_id': key_id,
            'verify_instruction': 'python scripts/verify_certificate.py <evidence_id>',
        }, separators=(',', ':'))
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=4, border=2)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        buf = io.BytesIO()
        img.save(buf)
        svg_data = buf.getvalue().decode('utf-8')
        qr_html = f'''
        <div class="qr-box">
          {svg_data}
          <div class="qr-label">Scan to verify · Evidence ID: {ev_id}</div>
        </div>'''
    except ImportError:
        qr_html = f'<div class="qr-box"><div class="qr-label">QR code requires <code>qrcode[svg]</code> library. Evidence ID: {ev_id}</div></div>'

    input_meta  = evidence_package.get('input', {})
    op_meta     = evidence_package.get('operation', {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensic Evidence Certificate — {ev_id}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="cert-page">
  <div class="cert-header">
    <div class="cert-seal">🔏</div>
    <div class="cert-title">Forensic Evidence Certificate</div>
    <div class="cert-sub">SIH26149 — Integrated Forensic &amp; Sanitization Workstation · NTRO Problem Statement</div>
    <div class="cert-sub">Generated: {now_iso}</div>
  </div>

  <div class="classification {classification}">
    {classification}
  </div>

  <div class="section">
    <div class="section-title">Case &amp; Evidence Identity</div>
    {_html_kv([
        ('Case ID', case_id),
        ('Case Title', case_title or '—'),
        ('Evidence ID', ev_id),
        ('Evidence Type', ev_type),
        ('Created', created_at),
        ('Signed', signed_at),
    ])}
  </div>

  <div class="section">
    <div class="section-title">Operation Details</div>
    {_html_kv([
        ('Operation', op_meta.get('method', op_meta.get('operation', '—'))),
        ('Scope', scope),
        ('Explanation', explanation),
    ])}
  </div>

  <div class="section">
    <div class="section-title">Cryptographic Integrity</div>
    {_html_kv([
        ('Signing Algorithm', algorithm),
        ('Key ID', key_id),
    ])}
    <div class="sig-box">
      <div style="font-size:10px;font-weight:700;color:#555;margin-bottom:4px;">EVIDENCE HASH (SHA-256)</div>
      <div class="sig-hash">{ev_hash}</div>
    </div>
    {f'<div class="sig-box" style="margin-top:8px;"><div style="font-size:10px;font-weight:700;color:#555;margin-bottom:4px;">ED25519 SIGNATURE</div><div class="sig-hash">{signature_hex[:64]}…</div></div>' if signature_hex else ''}
  </div>

  <div class="section">
    <div class="section-title">Independent Verification QR</div>
    {qr_html}
  </div>

  <div class="cert-footer">
    This certificate was generated by the SIH26149 Integrated Forensic &amp; Sanitization Workstation.<br>
    Verify offline: <code>python scripts/verify_certificate.py {ev_id}</code><br>
    Chain-of-custody audit log is stored in <code>data/audit/{case_id}.jsonl</code><br>
    Cryptographic signature verifiable against public key ID: <strong>{key_id}</strong>
  </div>
</div>
</body>
</html>"""
    return html


def generate_pdf_certificate(
    evidence_package: dict,
    output_path: str,
    case_title: Optional[str] = None,
) -> bool:
    """
    Generate a printable PDF certificate using ReportLab.
    Falls back to HTML if ReportLab is not available.

    Returns True if PDF was generated, False if fallback used.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm

        ev_id   = evidence_package.get('evidence_id', '—')
        case_id = evidence_package.get('case_id', '—')
        ev_type = evidence_package.get('evidence_type', '—')
        ev_hash = evidence_package.get('evidence_hash', '—')
        key_id  = evidence_package.get('key_id', '—')
        result  = evidence_package.get('result', {})
        classification = result.get('classification', 'UNVERIFIED')
        explanation    = result.get('explanation', '—')
        scope          = evidence_package.get('scope', '—')
        signed_at      = evidence_package.get('signed_at_utc', '—')
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        doc = SimpleDocTemplate(output_path, pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        title_style  = ParagraphStyle('CertTitle', parent=styles['Title'], fontSize=18, spaceAfter=8)
        label_style  = ParagraphStyle('Label', parent=styles['Normal'], fontSize=9, textColor=colors.grey, spaceBefore=6)
        value_style  = ParagraphStyle('Value', parent=styles['Normal'], fontSize=10, fontName='Courier')
        normal_style = styles['Normal']

        cls_color = {
            'VERIFIED': colors.green, 'VERIFIED_WITHIN_SCOPE': colors.orange,
            'UNVERIFIED': colors.grey, 'INVALID': colors.red,
        }.get(classification, colors.grey)

        story = [
            Paragraph('FORENSIC EVIDENCE CERTIFICATE', title_style),
            Paragraph('SIH26149 — Integrated Forensic & Sanitization Workstation', normal_style),
            Paragraph(f'Generated: {now_iso}', label_style),
            HRFlowable(width="100%", thickness=2, color=colors.HexColor('#16213e'), spaceAfter=12),
            Paragraph(f'Classification: {classification}', ParagraphStyle(
                'CLS', parent=styles['Normal'], fontSize=14, fontName='Helvetica-Bold',
                textColor=cls_color, spaceBefore=8, spaceAfter=8
            )),
            HRFlowable(width="100%", thickness=1, spaceAfter=8),
        ]

        rows_data = [
            ('Evidence ID:', ev_id),
            ('Case ID:', case_id),
            ('Case Title:', case_title or '—'),
            ('Evidence Type:', ev_type),
            ('Signed At:', signed_at),
            ('Scope:', scope[:120] + '…' if len(scope) > 120 else scope),
            ('Explanation:', explanation[:120] + '…' if len(explanation) > 120 else explanation),
            ('Signing Algorithm:', 'Ed25519'),
            ('Key ID:', key_id),
            ('Evidence Hash (SHA-256):', ev_hash),
        ]

        table = Table([[Paragraph(k, label_style), Paragraph(v, value_style)] for k, v in rows_data],
                      colWidths=[4.5*cm, 12*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f8f8fc')]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#ddddee')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
        story.append(Spacer(1, 24))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#16213e')))
        story.append(Paragraph(
            f'Verify offline: python scripts/verify_certificate.py {ev_id}',
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
        ))

        doc.build(story)
        return True

    except ImportError:
        # Fallback: write HTML
        html = generate_html_certificate(evidence_package, case_title)
        html_path = output_path.replace('.pdf', '.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return False
