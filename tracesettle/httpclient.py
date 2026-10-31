"""HTTP client built on the standard library.

Responsibilities:
  * timeouts on every request
  * bounded retries with backoff, only for retryable outcomes
  * classification of every failure into a :class:`SourceStatus`
  * never logging or storing credentials
  * optional TTL caching of read-only GET responses, and a per-host rate limit

The client never raises for expected network conditions; it returns a
:class:`FetchResult` so adapters can map the outcome to evidence.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from . import config
from .cache import TtlCache
from .model import SourceStatus


@dataclass(frozen=True)
class FetchResult:
    status: SourceStatus
    http_status: int | None
    data: Any = None
    body_snippet: str | None = None
    message: str | None = None
    endpoint: str | None = None
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.status is SourceStatus.OK


_RETRYABLE = frozenset(
    {SourceStatus.RATE_LIMITED, SourceStatus.SERVER_ERROR, SourceStatus.TIMEOUT, SourceStatus.NETWORK_ERROR}
)

#: Read-only GET endpoints whose responses are cacheable for a short TTL.
#: Keyed on the URL path prefix; nothing that varies per investigation beyond the
#: URL itself is cached, and only successful responses are ever stored.
_CACHEABLE_GET_PREFIXES = (
    "/v0/status",           # 1Click status, keyed on the deposit address
    "/tx/",                 # Esplora transaction
    "/address/",            # Esplora address stats/history
)


def _classify_http(code: int) -> SourceStatus:
    if code == 401 or code == 403:
        return SourceStatus.UNAUTHORIZED
    if code == 404:
        return SourceStatus.NOT_FOUND
    if code == 429:
        return SourceStatus.RATE_LIMITED
    if 500 <= code <= 599:
        return SourceStatus.SERVER_ERROR
    if 400 <= code <= 499:
        return SourceStatus.MALFORMED
    return SourceStatus.OK


class HttpClient:
    """Minimal JSON-over-HTTP client with bounded retries.

    ``cache`` is an optional :class:`~tracesettle.cache.TtlCache`; when supplied,
    read-only GET responses on cacheable paths are stored and reused for the TTL.
    ``host_limiter`` is an optional :class:`~tracesettle.ratelimit.TokenBucketLimiter`
    that throttles calls per upstream host. Both are shared across requests by the
    server so the limits apply process-wide.
    """

    def __init__(
        self,
        timeout: float | None = None,
        max_attempts: int | None = None,
        backoff_base: float | None = None,
        opener: Any | None = None,
        sleeper: Any | None = None,
        cache: TtlCache | None = None,
        host_limiter: Any | None = None,
    ) -> None:
        self.timeout = config.REQUEST_TIMEOUT_SECONDS if timeout is None else timeout
        self.max_attempts = config.MAX_ATTEMPTS if max_attempts is None else max_attempts
        self.backoff_base = config.BACKOFF_BASE_SECONDS if backoff_base is None else backoff_base
        # ``opener`` is injectable so tests can supply canned responses.
        self._opener = opener if opener is not None else urllib.request.urlopen
        self._sleep = sleeper if sleeper is not None else time.sleep
        self._cache = cache
        self._host_limiter = host_limiter

    # -- public API ---------------------------------------------------------

    def get_json(self, url: str, params: dict[str, str] | None = None) -> FetchResult:
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return self._request(url, method="GET", body=None)

    def get_text(self, url: str) -> FetchResult:
        """Fetch a plain-text body (e.g. a raw Bitcoin transaction in hex).

        Esplora's ``/tx/{id}/hex`` returns the transaction as hex text, not JSON,
        so it cannot go through the JSON path. The body is returned verbatim in
        ``data`` after a whitespace strip; nothing is parsed or interpreted here.
        """
        return self._request(url, method="GET", body=None, expect_json=False)

    def post_json(self, url: str, payload: dict[str, Any]) -> FetchResult:
        body = json.dumps(payload).encode("utf-8")
        return self._request(url, method="POST", body=body)

    # -- internals ----------------------------------------------------------

    def _request(
        self, url: str, method: str, body: bytes | None, expect_json: bool = True
    ) -> FetchResult:
        # A cacheable GET is served from cache when possible, and a miss is
        # coalesced so concurrent identical requests trigger one network call.
        cache_key = self._cache_key(url, method, body, expect_json)
        if cache_key is not None:
            return self._cache.get_or_load(  # type: ignore[union-attr]
                cache_key,
                lambda: self._request_uncached(url, method, body, expect_json),
                cache_if=lambda result: result.status is SourceStatus.OK,
            )
        return self._request_uncached(url, method, body, expect_json)

    def _cache_key(
        self, url: str, method: str, body: bytes | None, expect_json: bool
    ) -> str | None:
        """A stable cache key for a read-only GET, or ``None`` when not cacheable."""
        if self._cache is None or method != "GET":
            return None
        path = urllib.parse.urlsplit(url).path
        if not any(path.startswith(prefix) for prefix in _CACHEABLE_GET_PREFIXES):
            return None
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return f"GET:{'json' if expect_json else 'text'}:{digest}"

    def _request_uncached(
        self, url: str, method: str, body: bytes | None, expect_json: bool = True
    ) -> FetchResult:
        headers = {
            "Accept": "application/json",
            "User-Agent": config.USER_AGENT,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"

        # A per-host budget stops one caller from exhausting a free public
        # endpoint's shared rate limit for everyone.
        host = urllib.parse.urlsplit(url).hostname
        if host and self._host_limiter is not None and not self._host_limiter.allow(host):
            return FetchResult(
                status=SourceStatus.RATE_LIMITED,
                http_status=None,
                message="local host rate limit reached",
                endpoint=url,
                attempts=0,
            )

        last: FetchResult | None = None
        for attempt in range(1, self.max_attempts + 1):
            result = self._attempt(url, method, body, headers, attempt, expect_json)
            if result.status is SourceStatus.OK or result.status is SourceStatus.NOT_FOUND:
                return result
            last = result
            if result.status not in _RETRYABLE or attempt >= self.max_attempts:
                return result
            self._sleep(self.backoff_base * (2 ** (attempt - 1)))
        return last or FetchResult(
            status=SourceStatus.NETWORK_ERROR, http_status=None, endpoint=url, message="no attempt made"
        )

    def _attempt(
        self,
        url: str,
        method: str,
        body: bytes | None,
        headers: dict[str, str],
        attempt: int,
        expect_json: bool = True,
    ) -> FetchResult:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener(request, timeout=self.timeout) as response:
                raw = response.read()
                code = getattr(response, "status", None) or getattr(response, "code", 200)
        except urllib.error.HTTPError as exc:  # non-2xx
            snippet = _safe_snippet(exc)
            return FetchResult(
                status=_classify_http(exc.code),
                http_status=exc.code,
                body_snippet=snippet,
                message=f"HTTP {exc.code}",
                endpoint=url,
                attempts=attempt,
            )
        except TimeoutError:
            return FetchResult(
                status=SourceStatus.TIMEOUT,
                http_status=None,
                message="request timed out",
                endpoint=url,
                attempts=attempt,
            )
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            status = SourceStatus.TIMEOUT if isinstance(reason, TimeoutError) else SourceStatus.NETWORK_ERROR
            return FetchResult(
                status=status,
                http_status=None,
                message=f"network error: {reason}",
                endpoint=url,
                attempts=attempt,
            )
        except (OSError, ValueError) as exc:
            return FetchResult(
                status=SourceStatus.NETWORK_ERROR,
                http_status=None,
                message=f"transport error: {exc}",
                endpoint=url,
                attempts=attempt,
            )

        if not expect_json:
            return FetchResult(
                status=SourceStatus.OK,
                http_status=code,
                data=raw.decode("utf-8", "replace").strip(),
                endpoint=url,
                attempts=attempt,
            )

        try:
            data = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return FetchResult(
                status=SourceStatus.MALFORMED,
                http_status=code,
                body_snippet=raw[:200].decode("utf-8", "replace"),
                message=f"malformed JSON: {exc}",
                endpoint=url,
                attempts=attempt,
            )
        return FetchResult(
            status=SourceStatus.OK, http_status=code, data=data, endpoint=url, attempts=attempt
        )


def _safe_snippet(exc: urllib.error.HTTPError) -> str | None:
    try:
        raw = exc.read()
    except Exception:  # noqa: BLE001 - snippet is best-effort diagnostics only
        return None
    if not raw:
        return None
    return raw[:200].decode("utf-8", "replace")
