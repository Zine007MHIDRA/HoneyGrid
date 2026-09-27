import html
import requests
from honeygrid.config import settings

RESEND_ENDPOINT = "https://api.resend.com/emails"

def send_password_reset_email(to_email: str, reset_link: str, minutes_valid: int) -> bool:
    """Sends the reset link through Resend. Returns False (and never raises) when email isn't
    configured or delivery fails; the caller's response must not depend on the outcome."""
    if not settings.RESEND_API_KEY:
        if not settings.IS_PRODUCTION:
            # Local development convenience only: production never writes reset links to logs
            print(f"[dev] Password reset link for {to_email}: {reset_link}")
        else:
            print("[!] Password reset requested but RESEND_API_KEY is not configured.")
        return False

    link = html.escape(reset_link, quote=True)
    body_html = f"""
    <div style="font-family:Helvetica,Arial,sans-serif;max-width:520px;color:#111214">
      <div style="background:#0B0B0C;color:#F4F4F1;padding:16px 20px;font-weight:800;font-size:18px">HoneyGrid Sentinel</div>
      <div style="padding:20px;border:1px solid #D6D6D1;border-top:0">
        <p style="margin:0 0 12px">Someone asked to reset the password for this HoneyGrid operator account.</p>
        <p style="margin:0 0 20px"><a href="{link}" style="display:inline-block;background:#111214;color:#F4F4F1;padding:10px 16px;text-decoration:none;font-weight:600">Choose a new password</a></p>
        <p style="margin:0 0 8px;color:#5A5C60;font-size:13px">The link works once and expires in {minutes_valid} minutes. Using it signs you out of every device.</p>
        <p style="margin:0;color:#5A5C60;font-size:13px">If you didn't ask for this, ignore this email; your password stays the same.</p>
      </div>
    </div>"""
    body_text = (
        "Someone asked to reset the password for this HoneyGrid operator account.\n\n"
        f"Choose a new password: {reset_link}\n\n"
        f"The link works once and expires in {minutes_valid} minutes. Using it signs you out of every device.\n"
        "If you didn't ask for this, ignore this email; your password stays the same.\n"
    )
    try:
        res = requests.post(
            RESEND_ENDPOINT,
            headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from": settings.EMAIL_FROM,
                "to": [to_email],
                "subject": "Reset your HoneyGrid password",
                "html": body_html,
                "text": body_text,
            },
            timeout=10,
        )
        if res.status_code >= 300:
            print(f"[!] Password reset email not sent: Resend returned {res.status_code}: {res.text[:200]}")
            return False
        return True
    except Exception as e:
        print(f"[!] Password reset email not sent: {e}")
        return False
