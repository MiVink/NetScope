"""Allow running the CLI directly: `python netscope/main.py ...`."""

import sys
from pathlib import Path


def main():
    # Make the package importable when this file is run as a script
    package_parent = str(Path(__file__).resolve().parent.parent)
    if package_parent not in sys.path:
        sys.path.insert(0, package_parent)

    from netscope.cli import app

    app()


if __name__ == "__main__":
    main()
