#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.12,<2", "uvicorn>=0.30"]
# ///
"""sandbox-mcp launcher.  Usage:  uv run sandbox_mcp.py --help   (or: python sandbox_mcp.py ...)

Optional extra: `pillow` enables automatic downscaling for view_image.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sbx.server import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
