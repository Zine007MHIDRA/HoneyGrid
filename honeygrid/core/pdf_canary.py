import io
from pathlib import Path
from typing import Tuple
from datetime import datetime, timezone
from honeygrid.config import settings
from honeygrid.models import Token
from honeygrid.database import save_token
from honeygrid.core.generator import generate_unique_token_id

def generate_canary_pdf_bytes(token_id: str, label: str = "Confidential Payroll Decoy", document_title: str = "Confidential Compensation Review") -> bytes:
    """
    Generates a realistic corporate PDF document with an embedded canary beacon link as in-memory bytes.
    """
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}?source=pdf"
    
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Header banner
        c.setFillColor(colors.HexColor("#721c24"))
        c.rect(40, height - 80, width - 80, 40, fill=True, stroke=False)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(60, height - 65, "INTERNAL USE ONLY - STRICTLY CONFIDENTIAL")
        
        # Title & Subtitle
        c.setFillColor(colors.HexColor("#222222"))
        c.setFont("Helvetica-Bold", 18)
        c.drawString(50, height - 120, document_title)
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.HexColor("#666666"))
        c.drawString(50, height - 138, f"Asset: {label} | Department of Executive Compensation")
        
        # Body text
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.HexColor("#333333"))
        text_lines = [
            "This document outlines executive compensation tiers, equity distributions,",
            "and restricted stock unit (RSU) vesting schedules for the current fiscal cycle.",
            "",
            "NOTICE: Any unauthorized viewing, copying, or dissemination of this document",
            "is strictly prohibited and audited by Sentinel enterprise logging systems.",
            "",
            "To access the encrypted verification portal and full schedule, click the secure link:",
        ]
        
        y = height - 180
        for line in text_lines:
            c.drawString(50, y, line)
            y -= 18
            
        # Clickable Link / URL text
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(colors.HexColor("#0056b3"))
        c.drawString(50, y - 10, canary_url)
        c.linkURL(canary_url, (50, y - 15, 450, y + 5), relative=0)
        
        c.save()
        buffer.seek(0)
        return buffer.getvalue()
    except Exception:
        # Minimalist valid raw PDF fallback with link annotation
        raw_pdf = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R] >> endobj
4 0 obj << /Length 160 >> stream
BT
/F1 14 Tf
50 700 Td
(CONFIDENTIAL: {label}) Tj
/F1 10 Tf
0 -30 Td
(Verify Access at Portal: {canary_url}) Tj
ET
endstream endobj
5 0 obj <<
  /Type /Annot
  /Subtype /Link
  /Rect [50 650 500 680]
  /A << /S /URI /URI ({canary_url}) >>
>> endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000222 00000 n
0000000430 00000 n
trailer << /Size 6 /Root 1 0 R >>
startxref
540
%%EOF
"""
        return raw_pdf.encode("latin-1")

def create_canary_pdf(output_path: str, label: str = "Confidential Payroll Decoy", document_title: str = "Confidential Compensation Review") -> Tuple[Token, str]:
    """
    Generates a realistic corporate PDF document with an embedded canary beacon link, saves to disk if possible,
    and returns the Token model.
    """
    token_id = generate_unique_token_id("pdf")
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}?source=pdf"
    
    pdf_bytes = generate_canary_pdf_bytes(token_id, label, document_title)
    
    resolved_path = output_path
    try:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "wb") as f:
            f.write(pdf_bytes)
        resolved_path = str(out_file.resolve())
    except Exception as e:
        print(f"[!] Warning: Could not write PDF to disk ({e}), in-memory generation remains available.")
        
    token = Token(
        id=token_id,
        token_type="canary_pdf",
        label=label,
        description=f"Canary PDF decoy document: {label}",
        created_at=datetime.now(timezone.utc).isoformat(),
        metadata={"canary_url": canary_url, "file_path": resolved_path}
    )
    save_token(token)
    return token, resolved_path

