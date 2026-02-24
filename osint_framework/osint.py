#!/usr/bin/env python3
"""
OSINT Framework CLI Entry Point
Usage:
  python osint.py --help
  python osint.py scan domain example.com
"""
try:
    from osint_framework.cli.main import app
except ModuleNotFoundError:
    # Backward compatibility when executed from within the package directory.
    from cli.main import app

if __name__ == "__main__":
    app()
