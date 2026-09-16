"""Unit tests for web_security_guard.sri module."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from web_security_guard.sri import (
    compute_sri_hash,
    extract_sri_targets,
    hash_file,
    inject_sri_into_html,
)


def test_compute_sri_hash_known_vectors() -> None:
    content = "console.log('web-security-guard');"
    content_bytes = content.encode("utf-8")

    # sha256
    expected_sha256 = "sha256-" + base64.b64encode(hashlib.sha256(content_bytes).digest()).decode("ascii")
    assert compute_sri_hash(content, algorithm="sha256") == expected_sha256
    assert compute_sri_hash(content_bytes, algorithm="SHA256") == expected_sha256

    # sha384 (default)
    expected_sha384 = "sha384-" + base64.b64encode(hashlib.sha384(content_bytes).digest()).decode("ascii")
    assert compute_sri_hash(content) == expected_sha384
    assert compute_sri_hash(content, algorithm="sha384") == expected_sha384

    # sha512
    expected_sha512 = "sha512-" + base64.b64encode(hashlib.sha512(content_bytes).digest()).decode("ascii")
    assert compute_sri_hash(content, algorithm="sha512") == expected_sha512


def test_compute_sri_hash_unsupported_algorithm() -> None:
    with pytest.raises(ValueError, match="Unsupported SRI algorithm"):
        compute_sri_hash("test", algorithm="md5")
    with pytest.raises(ValueError, match="Unsupported SRI algorithm"):
        compute_sri_hash("test", algorithm="sha1")


def test_hash_file(tmp_path: Path) -> None:
    sample_file = tmp_path / "bundle.min.js"
    content = "function guard() { return true; }"
    sample_file.write_text(content, encoding="utf-8")

    expected_hash = compute_sri_hash(content, algorithm="sha384")
    file_hash = hash_file(sample_file, algorithm="sha384")
    assert file_hash == expected_hash

    # Missing file error
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "non_existent.js")

    # Unsupported algorithm error
    with pytest.raises(ValueError, match="Unsupported SRI algorithm"):
        hash_file(sample_file, algorithm="ripemd160")


def test_extract_sri_targets() -> None:
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha384-old" crossorigin="anonymous">
        <link rel="icon" href="/favicon.ico">
        <script src="https://cdn.example.com/app.js"></script>
        <script>console.log("inline");</script>
      </head>
      <body>
        <link href="/theme.css" rel="stylesheet" />
      </body>
    </html>
    """
    targets = extract_sri_targets(html)
    assert len(targets) == 3

    urls = [t["url"] for t in targets]
    assert "https://cdn.example.com/style.css" in urls
    assert "https://cdn.example.com/app.js" in urls
    assert "/theme.css" in urls


def test_inject_sri_into_html_empty_hashes() -> None:
    html = '<script src="/app.js"></script>'
    assert inject_sri_into_html(html, {}) == html


def test_inject_sri_into_html_basic_and_idempotent() -> None:
    html = """<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" href="https://cdn.example.com/styles.css">
    <script src="https://cdn.example.com/app.js"></script>
  </head>
  <body></body>
</html>"""

    resource_hashes = {
        "https://cdn.example.com/styles.css": "sha384-STYLE_HASH_123",
        "https://cdn.example.com/app.js": "sha384-SCRIPT_HASH_456",
    }

    injected = inject_sri_into_html(html, resource_hashes)

    assert 'integrity="sha384-STYLE_HASH_123"' in injected
    assert 'integrity="sha384-SCRIPT_HASH_456"' in injected
    assert 'crossorigin="anonymous"' in injected

    # Test idempotency: re-running on injected HTML should not duplicate attributes
    re_injected = inject_sri_into_html(injected, resource_hashes)
    assert re_injected == injected
    assert injected.count('integrity="sha384-STYLE_HASH_123"') == 1
    assert injected.count('integrity="sha384-SCRIPT_HASH_456"') == 1


def test_inject_sri_basename_and_relative_matching() -> None:
    html = """
    <script src="/static/js/vendor.min.js?v=2.0.1"></script>
    <link rel="stylesheet" href="./assets/main.css" />
    """

    resource_hashes = {
        "vendor.min.js": "sha256-VENDOR_HASH",
        "main.css": "sha256-MAIN_CSS_HASH",
    }

    injected = inject_sri_into_html(html, resource_hashes)
    assert 'integrity="sha256-VENDOR_HASH"' in injected
    assert 'integrity="sha256-MAIN_CSS_HASH"' in injected


def test_inject_sri_overwrite_existing() -> None:
    html = '<script src="/app.js" integrity="sha384-OLD" crossorigin="anonymous"></script>'

    # With overwrite_existing=True (default)
    updated = inject_sri_into_html(html, {"/app.js": "sha384-NEW"})
    assert 'integrity="sha384-NEW"' in updated
    assert 'sha384-OLD' not in updated

    # With overwrite_existing=False
    kept = inject_sri_into_html(html, {"/app.js": "sha384-NEW"}, overwrite_existing=False)
    assert 'integrity="sha384-OLD"' in kept
