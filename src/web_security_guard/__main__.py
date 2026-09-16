#!/usr/bin/env python3
"""Package main execution entrypoint for python -m web_security_guard."""

import sys
from web_security_guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
