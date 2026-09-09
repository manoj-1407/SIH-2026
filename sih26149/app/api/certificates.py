"""
Forensic Evidence Certificate API router — SIH26149.
"""
import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from typing import Optional

from app.api.deps import evidence_store, case_store
from app.api.validation import validate_case_id
from app.api.evidence import validate_evidence_id
from app.core.certificate import generate_html_certificate, generate_pdf_certificate

router = APIRouter(prefix="/evidence", tags=["certificates"])


@router.get("/{evidence_id}/certificate.html", response_class=HTMLResponse)
def get_certificate_html(evidence_id: str):
    """
    Generate and display an interactive, printable forensic evidence certificate
    with cryptographic verification QR code.
    """
    validate_evidence_id(evidence_id)
    try:
        pkg = evidence_store.get(evidence_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    case_id = pkg.get("case_id")
    case_title = None
    if case_id:
        try:
            case = case_store.get(case_id)
            if case:
                case_title = case.get("title") if isinstance(case, dict) else getattr(case, "title", None)
        except Exception:
            pass

    html = generate_html_certificate(pkg, case_title=case_title)
    return HTMLResponse(content=html, media_type="text/html")


@router.get("/{evidence_id}/certificate.pdf")
def get_certificate_pdf(evidence_id: str):
    """
    Generate and download a PDF forensic evidence certificate.
    Falls back to HTML if reportlab is not installed or errors out.
    """
    validate_evidence_id(evidence_id)
    try:
        pkg = evidence_store.get(evidence_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    case_id = pkg.get("case_id", "general")
    case_title = None
    if case_id:
        try:
            case = case_store.get(case_id)
            if case:
                case_title = case.get("title") if isinstance(case, dict) else getattr(case, "title", None)
        except Exception:
            pass

    try:
        out_dir = os.path.join(os.environ.get("SIH26149_DATA_DIR", "data"), "certificates")
        os.makedirs(out_dir, exist_ok=True)
        pdf_path = os.path.join(out_dir, f"{evidence_id}_certificate.pdf")

        success = generate_pdf_certificate(pkg, pdf_path, case_title=case_title)
        if success and os.path.exists(pdf_path):
            return FileResponse(
                pdf_path,
                media_type="application/pdf",
                filename=f"certificate_{evidence_id}.pdf"
            )
    except Exception:
        pass

    # Unconditional fail-safe fallback: return HTML certificate
    html = generate_html_certificate(pkg, case_title=case_title)
    return HTMLResponse(content=html, media_type="text/html")

