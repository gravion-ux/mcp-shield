"""Allow `python -m mcp_shield`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
