"""Download one file and refuse it unless its SHA-256 matches: python fetch.py <url> <destination> <sha256>."""

from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    url, destination, expected = sys.argv[1], Path(sys.argv[2]), sys.argv[3].lower()
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        print(f"::error title=Download verification failed::{url} has SHA-256 {digest}, expected {expected}", flush=True)
        return 1
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    print(f"Fetched {url} ({len(data)} bytes, SHA-256 verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
