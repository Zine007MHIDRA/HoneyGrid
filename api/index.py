import sys
from pathlib import Path

# Add project root to sys.path so honeygrid package can be imported
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from honeygrid.server.listener import app
