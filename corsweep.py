#!/usr/bin/env python3
"""
CORSweep - a high-signal CORS misconfiguration scanner.

Design goal: minimise false positives. A finding is only reported when the
server *provably* reflects an attacker-controllable Origin (exact match) or
returns a known-dangerous value. Wildcards without credentials are reported
as informational, not as vulnerabilities, because they cannot leak
credentialed data.

Author: blackboxpentester
License: MIT
"""

import argparse
import asyncio
import csv
import json
import sys
from dataclasses import dataclass, asdict, field
from typing import Optional
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency. Run:  pip install httpx")


# ----------------------------- colours --------------------------------------
class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    GRY = "\033[90m"
    BLD = "\033[1m"
    RST = "\033[0m"

    @classmethod
    def strip(cls):
        for k in ("RED", "YEL", "GRN", "CYN", "GRY", "BLD", "RST"):
            setattr(cls, k, "")


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH": C.RED,
    "MEDIUM": C.YEL,
    "LOW": C.CYN,
    "INFO": C.GRY,
}


# ----------------------------- data model -----------------------------------
@dataclass
class Finding:
    url: str
    test: str                 # which bypass class fired
    origin_sent: str
    acao: Optional[str]       # Access-Control-Allow-Origin returned
    acac: bool                # Access-Control-Allow-Credentials == true
    severity: str
    detail: str


@dataclass
class Target:
    url: str
    findings: list = field(default_factory=list)
    error: Optional[str] = None


# ------------------------- origin payload builder ---------------------------
def build_origin_payloads(url: str):
    """
    Generate (label, origin, hint) tuples tailored to the target host.
    Each targets a specific server-side validation flaw.
    """
    p = urlparse(url)
    host = p.hostname or ""
    scheme = p.scheme or "https"

    # A random, obviously-external origin. Exact reflection of THIS is the
    # single strongest signal that origin validation is broken.
    arbitrary = "https://cw-evil-8f3a2b.com"

    payloads = [
        ("reflect_arbitrary", arbitrary,
         "Server reflects an arbitrary external origin"),
        ("null_origin", "null",
         "Server allows the 'null' origin (sandboxed iframe / redirect)"),
        ("http_downgrade", f"http://{host}",
         "HTTPS site trusts an http:// origin (MITM readable)"),
        ("prefix_bypass", f"{scheme}://{host}.cw-evil-8f3a2b.com",
         "Trusted host used as a prefix (startsWith / weak regex)"),
        ("suffix_bypass", f"{scheme}://cw-evil-8f3a2b{host}",
         "Trusted host used as a suffix (endsWith / unanchored)"),
        ("unescaped_dot", f"{scheme}://{host.replace('.', 'x', 1)}",
         "Unescaped '.' in a validation regex"),
        ("special_char", f"{scheme}://{host}%60.cw-evil-8f3a2b.com",
         "Special char parser confusion (backtick/underscore tricks)"),
        ("subdomain_trust", f"{scheme}://cw-sub.{host}",
         "Trusts arbitrary subdomains (risk if subdomain takeover)"),
    ]
    return payloads


# ------------------------------ core test -----------------------------------
def normalise(value: Optional[str]) -> Optional[str]:
    return value.strip().rstrip("/").lower() if value else value


def classify(label, origin_sent, acao, acac, host) -> Optional[Finding]:
    """
    Decide whether a single (origin -> response) pair is a real finding.
    Returns None if the response is safe for this test.
    """
    if acao is None:
        return None

    acao_n = normalise(acao)
    origin_n = normalise(origin_sent)
    host_n = (host or "").lower()

    # Wildcard: cannot carry credentials -> informational only.
    if acao_n == "*":
        if label == "reflect_arbitrary":
            return Finding(
                url="", test="wildcard", origin_sent=origin_sent, acao=acao,
                acac=acac, severity="LOW",
                detail="ACAO: * (wildcard). Not credential-exploitable, but "
                       "any site can read non-credentialed responses.")
        return None

    # The decisive check: does the server echo back EXACTLY what we sent?
    reflected = acao_n == origin_n

    if not reflected:
        # ACAO present but locked to some fixed value -> safe for this probe.
        return None

    # From here: reflection confirmed. Score by exploitability.
    cred = acac is True

    if label == "reflect_arbitrary":
        sev = "CRITICAL" if cred else "MEDIUM"
        d = ("Arbitrary origin reflected with credentials -> cross-origin "
             "theft of authenticated data." if cred else
             "Arbitrary origin reflected (no credentials) -> leaks "
             "non-authenticated responses to any site.")
    elif label == "null_origin":
        sev = "HIGH" if cred else "MEDIUM"
        d = ("'null' origin trusted + credentials -> exploitable via a "
             "sandboxed iframe." if cred else
             "'null' origin trusted (no credentials).")
    elif label == "http_downgrade":
        sev = "MEDIUM" if cred else "LOW"
        d = "HTTPS endpoint trusts an http:// origin; a network MITM can read responses."
    elif label in ("prefix_bypass", "suffix_bypass", "unescaped_dot",
                   "special_char"):
        sev = "HIGH" if cred else "MEDIUM"
        d = f"Origin validation bypass ({label}) — attacker-controlled domain accepted."
    elif label == "subdomain_trust":
        sev = "LOW"
        d = "Arbitrary subdomain trusted; exploitable only with a subdomain takeover."
    else:
        sev = "MEDIUM"
        d = "Origin reflected."

    return Finding(url="", test=label, origin_sent=origin_sent, acao=acao,
                   acac=cred, severity=sev, detail=d)


async def scan_target(client, url, headers, preflight, sem) -> Target:
    t = Target(url=url)
    host = urlparse(url).hostname
    payloads = build_origin_payloads(url)

    async with sem:
        for label, origin, _hint in payloads:
            req_headers = dict(headers)
            req_headers["Origin"] = origin
            method = "OPTIONS" if preflight else "GET"
            if preflight:
                req_headers.setdefault("Access-Control-Request-Method", "GET")
            try:
                r = await client.request(method, url, headers=req_headers)
            except Exception as e:              # noqa: BLE001
                if t.error is None:
                    t.error = f"{type(e).__name__}: {e}"
                continue

            acao = r.headers.get("access-control-allow-origin")
            acac = (r.headers.get("access-control-allow-credentials", "")
                    .strip().lower() == "true")

            f = classify(label, origin, acao, acac, host)
            if f:
                f.url = url
                t.findings.append(f)

    # de-dupe identical (test,severity) rows
    seen, uniq = set(), []
    for f in sorted(t.findings, key=lambda x: SEV_ORDER[x.severity]):
        key = (f.test, f.severity)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    t.findings = uniq
    return t


# ------------------------------- runner -------------------------------------
async def run(urls, args):
    headers = {"User-Agent": args.user_agent}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    limits = httpx.Limits(max_connections=args.concurrency)
    sem = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(
        verify=not args.insecure, follow_redirects=True,
        timeout=args.timeout, limits=limits, cookies=cookies,
        proxy=args.proxy or None,
    ) as client:
        tasks = [scan_target(client, u, headers, args.preflight, sem)
                 for u in urls]
        return await asyncio.gather(*tasks)


# ------------------------------- output -------------------------------------
def print_report(targets, only_vuln):
    total = 0
    for t in targets:
        rows = t.findings
        if only_vuln:
            rows = [f for f in rows if f.severity not in ("INFO", "LOW")]
        if t.error and not rows:
            print(f"{C.GRY}[err]{C.RST} {t.url}  ({t.error})")
            continue
        if not rows:
            print(f"{C.GRN}[ok ]{C.RST} {t.url}")
            continue
        print(f"\n{C.BLD}{t.url}{C.RST}")
        for f in rows:
            total += 1
            col = SEV_COLOR[f.severity]
            cred = "creds" if f.acac else "no-creds"
            print(f"  {col}{f.severity:<8}{C.RST} {f.test:<16} "
                  f"[{cred}]  origin={f.origin_sent}")
            print(f"           {C.GRY}{f.detail}{C.RST}")
    print(f"\n{C.BLD}{total}{C.RST} actionable finding(s) across "
          f"{len(targets)} target(s).")


def write_json(targets, path):
    out = [{"url": t.url, "error": t.error,
            "findings": [asdict(f) for f in t.findings]} for t in targets]
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)


def write_csv(targets, path):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "severity", "test", "origin_sent", "acao",
                    "credentials", "detail"])
        for t in targets:
            for f in t.findings:
                w.writerow([f.url, f.severity, f.test, f.origin_sent,
                            f.acao, f.acac, f.detail])


# ------------------------------- CLI ----------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="corsweep",
        description="High-signal CORS misconfiguration scanner.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="single target URL")
    g.add_argument("-l", "--list", help="file with one URL per line")
    ap.add_argument("-c", "--cookie", help="Cookie header for authenticated tests")
    ap.add_argument("-H", "--header", action="append",
                    help="extra header 'K: V' (repeatable)")
    ap.add_argument("-t", "--concurrency", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--preflight", action="store_true",
                    help="use OPTIONS preflight instead of GET")
    ap.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 for Burp")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="skip TLS verification")
    ap.add_argument("--user-agent", default="CORSweep/1.0")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--csv", dest="csv_out")
    ap.add_argument("--only-vuln", action="store_true",
                    help="hide OK/INFO/LOW rows in terminal")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.strip()
        for k in SEV_COLOR:
            SEV_COLOR[k] = ""

    if args.url:
        urls = [args.url]
    else:
        with open(args.list) as fh:
            urls = [ln.strip() for ln in fh if ln.strip()
                    and not ln.startswith("#")]

    urls = [u if u.startswith("http") else "https://" + u for u in urls]

    targets = asyncio.run(run(urls, args))

    print_report(targets, args.only_vuln)
    if args.json_out:
        write_json(targets, args.json_out)
        print(f"{C.GRY}JSON -> {args.json_out}{C.RST}")
    if args.csv_out:
        write_csv(targets, args.csv_out)
        print(f"{C.GRY}CSV  -> {args.csv_out}{C.RST}")

    # exit code 2 if any HIGH/CRITICAL -> CI-friendly
    for t in targets:
        if any(f.severity in ("CRITICAL", "HIGH") for f in t.findings):
            sys.exit(2)


if __name__ == "__main__":
    main()
