"""Async HTTP client with retries, rate limiting, soft-404 detection."""
from __future__ import annotations

import asyncio
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from .logger import get_logger
from .settings import DEFAULT_HEADERS, SOFT_404_MARKERS, USER_AGENTS


@dataclass
class HttpResponse:
    status: int
    body: bytes
    headers: dict = field(default_factory=dict)
    url: str = ""
    soft_404: bool = False

    @property
    def ok(self) -> bool:
        return self.status == 200 and not self.soft_404 and len(self.body) > 0


class HttpClient:
    """Async client with concurrency, retries and per-host rate limiting."""

    def __init__(
        self,
        concurrency: int = 16,
        timeout: float = 15.0,
        retries: int = 3,
        retry_backoff: float = 0.5,
        rate_limit: float = 0.0,  # seconds between requests per worker
        proxy: Optional[str] = None,
        verify_tls: bool = True,
        extra_headers: Optional[dict] = None,
        rotate_ua: bool = False,
        cookies: Optional[str] = None,
        auth: Optional[tuple[str, str]] = None,
    ) -> None:
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.retries = retries
        self.retry_backoff = retry_backoff
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.rotate_ua = rotate_ua
        self.sem = asyncio.Semaphore(concurrency)
        self.log = get_logger()

        self.headers = dict(DEFAULT_HEADERS)
        if not rotate_ua:
            self.headers["User-Agent"] = USER_AGENTS[0]
        if extra_headers:
            self.headers.update(extra_headers)
        if cookies:
            self.headers["Cookie"] = cookies

        self._auth = aiohttp.BasicAuth(*auth) if auth else None

        ssl_ctx = None
        if not verify_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        self.connector = aiohttp.TCPConnector(
            ssl=ssl_ctx if ssl_ctx else None,
            limit=concurrency * 2,
            ttl_dns_cache=300,
        )
        self._session: Optional[aiohttp.ClientSession] = None
        # 404 fingerprint (size + first bytes) – calibrated per host
        self._404_signature: dict[str, tuple[int, bytes]] = {}

    async def __aenter__(self) -> "HttpClient":
        self._session = aiohttp.ClientSession(
            connector=self.connector, timeout=self.timeout
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()
        await asyncio.sleep(0.05)

    # ------------------------------------------------------------------ core

    def _pick_ua(self) -> dict:
        if not self.rotate_ua:
            return self.headers
        h = dict(self.headers)
        h["User-Agent"] = random.choice(USER_AGENTS)
        return h

    async def calibrate_soft_404(self, base_url: str) -> None:
        """Hit a random unlikely URL to learn the soft-404 page fingerprint."""
        host = urlparse(base_url).netloc
        if host in self._404_signature:
            return
        rand = f"gitexpose-probe-{random.randint(10**9, 10**10)}"
        url = base_url.rstrip("/") + "/" + rand
        try:
            r = await self._raw_get(url)
            if r.status in (200, 206):
                self._404_signature[host] = (len(r.body), r.body[:64])
                self.log.debug(
                    f"soft-404 calibrated for {host}: status={r.status} "
                    f"len={len(r.body)}"
                )
        except Exception as e:
            self.log.debug(f"soft-404 calibration failed: {e}")

    def _is_soft_404(self, url: str, status: int, body: bytes) -> bool:
        host = urlparse(url).netloc
        if status in (200, 206):
            sig = self._404_signature.get(host)
            if sig and len(body) == sig[0] and body[:64] == sig[1]:
                return True
            for marker in SOFT_404_MARKERS:
                if marker in body[:2048]:
                    return True
        return False

    async def _raw_get(self, url: str) -> HttpResponse:
        assert self._session is not None
        async with self._session.get(
            url,
            headers=self._pick_ua(),
            proxy=self.proxy,
            ssl=False if not self.verify_tls else None,
            auth=self._auth,
            allow_redirects=True,
        ) as resp:
            body = await resp.read()
            return HttpResponse(
                status=resp.status,
                body=body,
                headers={k: v for k, v in resp.headers.items()},
                url=str(resp.url),
            )

    async def get(self, url: str, *, allow_404: bool = True) -> HttpResponse:
        async with self.sem:
            if self.rate_limit > 0:
                await asyncio.sleep(self.rate_limit)
            last_exc: Optional[Exception] = None
            for attempt in range(1, self.retries + 1):
                try:
                    self.log.payload(f"GET {url}")
                    r = await self._raw_get(url)
                    r.soft_404 = self._is_soft_404(url, r.status, r.body)
                    if r.soft_404:
                        self.log.trace(f"soft-404 detected for {url}")
                    self.log.http("GET", url, r.status, len(r.body))
                    if r.status >= 500 and attempt < self.retries:
                        await asyncio.sleep(self.retry_backoff * attempt)
                        continue
                    return r
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    last_exc = e
                    self.log.trace(f"attempt {attempt} failed for {url}: {e}")
                    if attempt < self.retries:
                        await asyncio.sleep(self.retry_backoff * attempt)
                        continue
            self.log.error(f"giving up on {url}: {last_exc}")
            return HttpResponse(status=0, body=b"", url=url)

    async def head(self, url: str) -> HttpResponse:
        async with self.sem:
            assert self._session is not None
            try:
                async with self._session.head(
                    url,
                    headers=self._pick_ua(),
                    proxy=self.proxy,
                    ssl=False if not self.verify_tls else None,
                    auth=self._auth,
                    allow_redirects=True,
                ) as resp:
                    self.log.http("HEAD", url, resp.status, 0)
                    return HttpResponse(status=resp.status, body=b"", url=str(resp.url))
            except Exception as e:
                self.log.trace(f"HEAD {url} failed: {e}")
                return HttpResponse(status=0, body=b"", url=url)
