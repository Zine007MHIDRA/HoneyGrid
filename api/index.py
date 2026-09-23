import sys
import os
from pathlib import Path

# Add project root and current working dir to sys.path so honeygrid package is discoverable on Vercel
BASE_DIR = Path(__file__).resolve().parent.parent
cwd = Path(os.getcwd())

for p in [str(BASE_DIR), str(cwd)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from honeygrid.server.listener import app
