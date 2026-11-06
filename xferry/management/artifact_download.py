"""Portable bounded reads for authenticated artifact metadata."""

from __future__ import annotations

import urllib.request
from http.client import HTTPMessage
from typing import IO, cast
from urllib.parse import urljoin, urlsplit


def _require_https(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("artifact metadata requires a credential-free HTTPS URL")


class _HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        _require_https(urljoin(request.full_url, new_url))
        return super().redirect_request(request, fp, code, message, headers, new_url)


class HttpsAssetReader:
    def read(self, url: str, max_bytes: int) -> bytes:
        _require_https(url)
        opener = urllib.request.build_opener(_HttpsRedirect())
        with opener.open(url, timeout=30) as response:
            _require_https(response.geturl())
            payload = cast(bytes, response.read(max_bytes + 1))
        if len(payload) > max_bytes:
            raise OSError("artifact metadata exceeds its size limit")
        return payload
