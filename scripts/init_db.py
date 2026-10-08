"""Initialize or refresh the SQLite learning-content database."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from revlearn import create_app
from revlearn.database import init_db


def main() -> None:
    app = create_app()
    with app.app_context():
        init_db()
        print(f"Learning database ready: {app.config['DATABASE']}")


if __name__ == "__main__":
    main()

