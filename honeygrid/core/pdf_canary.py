import os
from pathlib import Path
from typing import Tuple
from honeygrid.config import settings
from honeygrid.models import Token
from honeygrid.database import save_token
from honeygrid.core.generator import generate_unique_token_id

def create_canary_pdf(output_path: str, label: str = "Confidential Payroll Decoy", document_title: str = "Confidential Compensation Review") -> Tuple[Token, str]:
    """
    Generates a realistic corporate PDF document with an embedded canary beacon link and metadata.
    """
    token_id = generate_unique_token_id("pdf")
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}?source=pdf"
    
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Try using reportlab if available
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        
        c = canvas.Canvas(str(out_file), pagesize=letter)
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
        c.drawString(50, height - 138, "Authorized Personnel Only | Department of Executive Compensation")
        
        # Body text
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.HexColor("#333333"))
        text_lines = [
            "This document outlines executive salary adjustments, equity distribution tiers,",
            "and restricted stock unit (RSU) vesting schedules for the current fiscal quarter.",
            "",
            "NOTICE: Any unauthorized viewing, copying, or dissemination of this document",
            "is strictly prohibited and logged by corporate audit systems.",
            "",
            "To access the encrypted verification portal and full schedule, visit:",
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
    except ImportError:
        # Minimalist valid raw PDF fallback with link annotation
        raw_pdf = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R] >> endobj
4 0 obj << /Length 120 >> stream
BT
/F1 14 Tf
50 700 Td
(CONFIDENTIAL EXECUTIVE SALARY & BONUS REPORT 2026) Tj
/F1 10 Tf
0 -30 Td
(Verify Access: {canary_url}) Tj
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
0000000392 00000 n
trailer << /Size 6 /Root 1 0 R >>
startxref
500
%%EOF
"""
        with open(out_file, "w", encoding="latin-1") as f:
            f.write(raw_pdf)

    token = Token(
        id=token_id,
        token_type="canary_pdf",
        label=label,
        description=f"Canary PDF planted at {out_file}",
        created_at=datetime.now(timezone.utc).isoformat(),
        metadata={"canary_url": canary_url, "file_path": str(out_file.resolve())}
    )
    save_token(token)
    return token, str(out_file.resolve())
