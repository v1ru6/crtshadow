#!/usr/bin/env python3
import argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm

def fetch_entries(domain, use_https=True, verbose=False):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/114.0.5735.198 Safari/537.36"
        )
    }

    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET"])
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))

    if verbose:
        print(f"🔍 Fetching JSON from {url}")
    else:
        print(f"-> requesting {url}")

    resp = session.get(url, headers=headers, timeout=10)
    if resp.status_code == 503 and use_https:
        if verbose:
            print("⚠️  HTTPS 503; retrying over HTTP")
        else:
            print("   got 503 over HTTPS; retrying HTTP")
        return fetch_entries(domain, use_https=False, verbose=verbose)

    resp.raise_for_status()
    return resp.json()

def extract_names(entries, verbose=False):
    hosts = set()

    # parse CN + SAN fields
    loop_cert = tqdm(entries, desc="📄 certificates") if verbose else entries
    for cert in loop_cert:
        cn = cert.get("common_name", "").strip()
        if cn:
            hosts.add(cn)
        for name in cert.get("name_value", "").split():
            name = name.strip()
            if name:
                hosts.add(name)

    # clean wildcards + lowercase
    clean = set()
    loop_clean = tqdm(hosts, desc="🔧 cleaning") if verbose else hosts
    for h in loop_clean:
        if h.startswith("*."):
            h = h[2:]
        clean.add(h.lower())

    return clean

def main():
    parser = argparse.ArgumentParser(description="Pull subdomains from crt.sh")
    parser.add_argument("domain", help="e.g. cms.law")
    parser.add_argument(
        "-s", "--same",
        action="store_true",
        help="only include the main domain and its subdomains"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="write results to FILE (one per line)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="enable verbose mode (emojis, progress bars)"
    )
    args = parser.parse_args()

    domain = args.domain.lower()
    data = fetch_entries(domain, verbose=args.verbose)
    if args.verbose:
        print(f"🗂 Retrieved {len(data)} certificate entries\n")
    else:
        print(f"-> got {len(data)} entries")

    names = extract_names(data, verbose=args.verbose)

    if args.same:
        suffix = "." + domain
        names = {n for n in names if n == domain or n.endswith(suffix)}

    sorted_names = sorted(names)

    if args.output:
        with open(args.output, "w") as f:
            for n in sorted_names:
                f.write(n + "\n")
        if args.verbose:
            print(f"\n✅ Wrote {len(sorted_names)} entries to {args.output}")
        else:
            print(f"-> wrote {len(sorted_names)} entries to {args.output}")
    else:
        if args.verbose:
            print(f"\n✅ Found {len(sorted_names)} subdomains:\n")
        else:
            print(f"found {len(sorted_names)} entries:")
        for n in sorted_names:
            print(n)

if __name__ == "__main__":
    main()
