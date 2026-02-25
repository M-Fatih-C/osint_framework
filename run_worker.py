#!/usr/bin/env python3
"""Run the OSINT Framework background worker process (Redis queue mode)."""

from osint_framework.worker_main import main


if __name__ == "__main__":
    main()
