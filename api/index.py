import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mangum import Mangum

from app.main import app, initialize_database

_adapter = None
_initialized = False


def handler(event, context):
    global _adapter, _initialized
    if not _initialized:
        initialize_database()
        _initialized = True
    if _adapter is None:
        _adapter = Mangum(app, lifespan="off")
    return _adapter(event, context)
