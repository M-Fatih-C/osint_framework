#!/usr/bin/env python3
"""Run the OSINT Framework API server from the repository root."""

import os

import uvicorn


def main():
    host = os.getenv("OSINT_HOST", "127.0.0.1")
    port = int(os.getenv("OSINT_PORT", "8000"))
    uvicorn.run("osint_framework.api.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()

