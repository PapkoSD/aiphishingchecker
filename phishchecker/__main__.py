"""Start the Phishing Checker: python -m phishchecker"""

import argparse
import os
import threading
import warnings
import webbrowser

from waitress import serve

from .analyzer import email_model, url_model
from .app import create_app


def main():
    parser = argparse.ArgumentParser(prog="python -m phishchecker", description=__doc__)
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"),
                        help="address to listen on (default: 127.0.0.1, only this computer)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)),
                        help="port to listen on (default: 8000)")
    parser.add_argument("--no-browser", action="store_true",
                        default=os.environ.get("NO_BROWSER") == "1",
                        help="don't open the browser automatically")
    args = parser.parse_args()

    print("Loading the phishing models...")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        email_model()
        url_model()

    shown_host = "localhost" if args.host in ("127.0.0.1", "0.0.0.0") else args.host
    url = f"http://{shown_host}:{args.port}"
    print(f"\n  Phishing Checker is running at {url}\n  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, [url]).start()
    serve(create_app(), host=args.host, port=args.port, threads=4, _quiet=True)


if __name__ == "__main__":
    main()
