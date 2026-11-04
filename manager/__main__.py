"""`python3 <checkout>/manager project|serve ...`: what bin/appsec-compose dispatches to."""
import sys
from pathlib import Path

if not __package__:
    # Running the directory puts only the package itself on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yaml  # noqa: F401
except ImportError:
    print("ERROR: PyYAML is required on the host: python3 -m pip install pyyaml", file=sys.stderr)
    sys.exit(2)

from manager.cli import main  # noqa: E402

sys.exit(main(sys.argv[1:]))
