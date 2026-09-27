#!/usr/bin/env python3
"""Standalone runner for the CISO Assistant Web UI."""

import argparse
import webbrowser

from web import create_app


def main():
    parser = argparse.ArgumentParser(description="Run the CISO Assistant Web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind to (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000).")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode.")
    parser.add_argument("--open", action="store_true", help="Automatically open browser on launch.")
    args = parser.parse_args()

    app = create_app()

    if args.open:
        webbrowser.open(f"http://{args.host}:{args.port}")

    print(f"\n* Starting CISO Assistant Web UI at http://{args.host}:{args.port}")
    print("* Press Ctrl+C to stop the server\n")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
