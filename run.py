#!/usr/bin/env python3
"""EireScope — Run the OSINT Investigation Dashboard."""
import sys
import os
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eirescope.web.app import run_server


def main():
    parser = argparse.ArgumentParser(
        description="EireScope — Open-Source Intelligence Investigation Dashboard"
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="Port to listen on (default: 5000)"
    )
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
