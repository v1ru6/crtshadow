#!/usr/bin/env python3
"""
Download certificate transparency data from crt.sh and grab domain names.

By default it prints the full hostnames. Add **--trim** to strip the base
".<domain>" suffix so only the sub‑host part remains.

Examples
--------
# All names for cmslegal.com
$ python crtsh_subextractor.py cmslegal.com

# Only cmslegal.com and its sub‑domains
$ python crtsh_subextractor.py cmslegal.com --same

# List host parts only (events, api-test.ci, …)
$ python crtsh_subextractor.py cmslegal.com --trim
"""
from __future__ import annotations

import argparse
from typing import Iterable, List, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods={"GET"},
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s


def fetch(domain: str, https: bool = True, verbose: bool = False) -> List[dict]:
    """Return raw JSON from crt.sh. Falls back to HTTP on 503."""
    proto = "https" if https else "http"
    url = f"{proto}://crt.sh/?q=%25.{domain}&output=json"

    header = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/114.0.5735.198 Safari/537.36"
        )
    }

    if verbose:
        print(f"Fetching {url}")
    sess = _session()
    resp = sess.get(url, headers=header, timeout=10)

    # crt.sh sometimes blocks HTTPS; try HTTP once
    if resp.status_code == 503 and https:
        if verbose:
            print("HTTPS gave 503, retrying over HTTP …")
        return fetch(domain, https=False, verbose=verbose)

    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _clean(hosts: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for h in hosts:
        h = h.strip()
        if h.startswith("*."):
            h = h[2:]
        if h:
            out.add(h.lower())
    return out


def extract(entries: List[dict], verbose: bool = False) -> Set[str]:
    names: Set[str] = set()

    loop = tqdm(entries, desc="certificates") if verbose else entries
    for cert in loop:
        cn = cert.get("common_name", "")
        if cn:
            names.add(cn)
        for part in cert.get("name_value", "").split():
            if part:
                names.add(part)

    return _clean(names)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:  # pragma: no cover
    p = argparse.ArgumentParser(description="Extract hostnames from crt.sh")
    p.add_argument("domain", help="base domain, e.g. example.com")
    p.add_argument("-s", "--same", action="store_true",
                   help="only keep <domain> and its sub‑domains")
    p.add_argument("-t", "--trim", action="store_true",
                   help="strip the base suffix (output host part only)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write to FILE instead of stdout")
    p.add_argument("-v", "--verbose", action="store_true")

    args = p.parse_args()
    domain = args.domain.lower().strip()

    data = fetch(domain, verbose=args.verbose)
    if args.verbose:
        print(f"Received {len(data)} cert entries")

    names = extract(data, verbose=args.verbose)

    if args.same:
        suffix = "." + domain
        names = {n for n in names if n == domain or n.endswith(suffix)}

    if args.trim:
        stripped: Set[str] = set()
        suffix = "." + domain
        for n in names:
            if n == domain:
                continue  # would be empty after stripping
            if n.endswith(suffix):
                n = n[: -len(suffix)]
            stripped.add(n)
        names = stripped

    out = sorted(names)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print(f"Wrote {len(out)} lines to {args.output}")
    else:
        print("\n".join(out))


if __name__ == "__main__":
    main()
