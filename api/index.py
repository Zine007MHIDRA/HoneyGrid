import sys
import os
import traceback
from pathlib import Path

# Add project root and current working dir to sys.path so honeygrid can be found on Vercel
BASE_DIR = Path(__file__).resolve().parent.parent
cwd = Path(os.getcwd())

for p in [str(BASE_DIR), str(cwd)]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from honeygrid.server.listener import app
except Exception as e:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    app = FastAPI(title="HoneyGrid Vercel Recovery Mode")
    err_traceback = traceback.format_exc()

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def debug_error_handler(path: str):
        return HTMLResponse(
            f"""
            <html>
                <body style="font-family: monospace; padding: 30px; background: #0b0f19; color: #ef4444;">
                    <h2>HoneyGrid Serverless Startup Diagnostic</h2>
                    <p style="color: #cbd5e1;">A runtime exception occurred during serverless cold start:</p>
                    <pre style="background: #1e293b; color: #f8fafc; padding: 20px; border-radius: 8px; overflow-x: auto;">{err_traceback}</pre>
                </body>
            </html>
            """,
            status_code=500
        )
