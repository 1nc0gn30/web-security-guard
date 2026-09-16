"""Subresource Integrity (SRI) Hashing and HTML Injection Engine.

Provides cryptographic SRI hash computation (sha256, sha384, sha512) for in-memory
content and filesystem assets, as well as idempotent HTML AST/regex injection for
<script> and <link rel="stylesheet"> tags.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from web_security_guard.compat import resolve_path

SUPPORTED_ALGORITHMS: Set[str] = {"sha256", "sha384", "sha512"}


def compute_sri_hash(content: Union[bytes, str], algorithm: str = "sha384") -> str:
    """Compute standard Subresource Integrity (SRI) hash string for arbitrary content.

    Args:
        content: Raw bytes or UTF-8 string to hash.
        algorithm: Cryptographic hash algorithm: 'sha256', 'sha384', or 'sha512' (default: sha384).

    Returns:
        Formatted SRI string in the format '<algorithm>-<base64_digest>'.

    Raises:
        ValueError: If an unsupported hashing algorithm is provided.
    """
    alg = algorithm.lower().strip()
    if alg not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported SRI algorithm '{algorithm}'. Must be one of: {', '.join(sorted(SUPPORTED_ALGORITHMS))}."
        )

    raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
    digest = hashlib.new(alg, raw_bytes).digest()
    b64_digest = base64.b64encode(digest).decode("ascii")
    return f"{alg}-{b64_digest}"


def hash_file(
    file_path: Union[str, Path],
    algorithm: str = "sha384",
    chunk_size: int = 65536,
) -> str:
    """Compute standard SRI hash string for a file on the local filesystem.

    Args:
        file_path: Path to the target file.
        algorithm: Cryptographic algorithm: 'sha256', 'sha384', or 'sha512' (default: sha384).
        chunk_size: Size of chunk in bytes for streaming file reads (default: 64KB).

    Returns:
        Formatted SRI string in the format '<algorithm>-<base64_digest>'.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If an unsupported hashing algorithm is provided.
    """
    alg = algorithm.lower().strip()
    if alg not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported SRI algorithm '{algorithm}'. Must be one of: {', '.join(sorted(SUPPORTED_ALGORITHMS))}."
        )

    resolved = resolve_path(file_path)
    if not resolved.is_file():
        raise FileNotFoundError(f"Cannot compute SRI hash: file not found at '{resolved}'.")

    hasher = hashlib.new(alg)
    with open(resolved, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)

    b64_digest = base64.b64encode(hasher.digest()).decode("ascii")
    return f"{alg}-{b64_digest}"


_ATTR_REGEX = re.compile(
    r'([a-zA-Z0-9_\-:]+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+)))?',
    re.IGNORECASE,
)


def _parse_attributes(tag_inside: str) -> Dict[str, str]:
    """Parse HTML attributes from the inside of a tag string."""
    attrs: Dict[str, str] = {}
    for match in _ATTR_REGEX.finditer(tag_inside):
        name = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else (
            match.group(3) if match.group(3) is not None else (
                match.group(4) if match.group(4) is not None else ""
            )
        )
        attrs[name] = val
    return attrs


def extract_sri_targets(html_str: str) -> List[Dict[str, Any]]:
    """Extract all script and stylesheet link tags eligible for SRI from an HTML document.

    Args:
        html_str: HTML document content string.

    Returns:
        List of dictionaries with keys: 'tag_type', 'url', 'integrity', 'crossorigin', 'raw_tag'.
    """
    targets: List[Dict[str, Any]] = []

    # 1. Scripts: <script ...>
    script_pattern = re.compile(r'<script\b([^>]*)>', re.IGNORECASE)
    for m in script_pattern.finditer(html_str):
        raw_tag = m.group(0)
        attrs = _parse_attributes(m.group(1))
        src = attrs.get("src")
        if src:
            targets.append({
                "tag_type": "script",
                "url": src,
                "integrity": attrs.get("integrity"),
                "crossorigin": attrs.get("crossorigin"),
                "raw_tag": raw_tag,
            })

    # 2. Links: <link ...>
    link_pattern = re.compile(r'<link\b([^>]*)>', re.IGNORECASE)
    for m in link_pattern.finditer(html_str):
        raw_tag = m.group(0)
        attrs = _parse_attributes(m.group(1))
        rel = attrs.get("rel", "").lower()
        href = attrs.get("href")
        if href and ("stylesheet" in rel or "preload" in rel):
            targets.append({
                "tag_type": "link",
                "url": href,
                "integrity": attrs.get("integrity"),
                "crossorigin": attrs.get("crossorigin"),
                "raw_tag": raw_tag,
            })

    return targets


def _find_matching_hash(url: str, resource_hashes: Dict[str, str]) -> Optional[str]:
    """Find matching hash in resource_hashes by exact URL, normalized path, or basename."""
    if url in resource_hashes:
        return resource_hashes[url]

    # Try stripped query params
    url_no_query = url.split("?")[0].split("#")[0]
    if url_no_query in resource_hashes:
        return resource_hashes[url_no_query]

    # Try basename matching if provided
    basename = Path(url_no_query).name
    if basename in resource_hashes:
        return resource_hashes[basename]

    # Try matching without leading slash
    if url_no_query.startswith("/") and url_no_query[1:] in resource_hashes:
        return resource_hashes[url_no_query[1:]]

    # Try matching with leading slash
    if not url_no_query.startswith("/") and f"/{url_no_query}" in resource_hashes:
        return resource_hashes[f"/{url_no_query}"]

    return None


def inject_sri_into_html(
    html_str: str,
    resource_hashes: Dict[str, str],
    default_crossorigin: str = "anonymous",
    overwrite_existing: bool = True,
) -> str:
    """Inject SRI integrity and crossorigin attributes into HTML <script> and <link> tags.

    Guarantees idempotency: re-running on already injected HTML will update hashes cleanly
    without duplicating integrity or crossorigin attributes.

    Args:
        html_str: The source HTML document string.
        resource_hashes: Mapping from resource URL / path to SRI hash string.
        default_crossorigin: Crossorigin attribute value to attach ('anonymous' or 'use-credentials').
        overwrite_existing: Whether to overwrite existing integrity attributes.

    Returns:
        Modified HTML document string with injected SRI attributes.
    """
    if not resource_hashes:
        return html_str

    # Process script tags
    def replace_script(match: re.Match) -> str:
        full_match = match.group(0)
        inside = match.group(1)
        attrs = _parse_attributes(inside)
        src = attrs.get("src")
        if not src:
            return full_match

        sri_hash = _find_matching_hash(src, resource_hashes)
        if not sri_hash:
            return full_match

        if "integrity" in attrs and not overwrite_existing:
            return full_match

        # Update or inject integrity and crossorigin
        new_inside = inside
        # Replace or strip existing integrity
        if "integrity" in attrs:
            new_inside = re.sub(
                r'\bintegrity\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)',
                f'integrity="{sri_hash}"',
                new_inside,
                flags=re.IGNORECASE,
            )
        else:
            new_inside = f'{new_inside.rstrip()} integrity="{sri_hash}"'

        # Ensure crossorigin is present
        if "crossorigin" not in attrs and default_crossorigin:
            new_inside = f'{new_inside.rstrip()} crossorigin="{default_crossorigin}"'

        return f"<script{new_inside}>"

    # Process link tags
    def replace_link(match: re.Match) -> str:
        full_match = match.group(0)
        inside = match.group(1)
        attrs = _parse_attributes(inside)
        href = attrs.get("href")
        rel = attrs.get("rel", "").lower()

        if not href or ("stylesheet" not in rel and "preload" not in rel):
            return full_match

        sri_hash = _find_matching_hash(href, resource_hashes)
        if not sri_hash:
            return full_match

        if "integrity" in attrs and not overwrite_existing:
            return full_match

        new_inside = inside
        if "integrity" in attrs:
            new_inside = re.sub(
                r'\bintegrity\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)',
                f'integrity="{sri_hash}"',
                new_inside,
                flags=re.IGNORECASE,
            )
        else:
            # Handle self closing slash if present at end
            is_self_closing = new_inside.rstrip().endswith("/")
            clean_inside = new_inside.rstrip()[:-1].rstrip() if is_self_closing else new_inside.rstrip()
            new_inside = f'{clean_inside} integrity="{sri_hash}"'
            if is_self_closing:
                new_inside = f"{new_inside} /"

        if "crossorigin" not in attrs and default_crossorigin:
            is_self_closing = new_inside.rstrip().endswith("/")
            clean_inside = new_inside.rstrip()[:-1].rstrip() if is_self_closing else new_inside.rstrip()
            new_inside = f'{clean_inside} crossorigin="{default_crossorigin}"'
            if is_self_closing:
                new_inside = f"{new_inside} /"

        return f"<link{new_inside}>"

    # Apply transformations
    script_pattern = re.compile(r'<script\b([^>]*)>', re.IGNORECASE)
    link_pattern = re.compile(r'<link\b([^>]*)>', re.IGNORECASE)

    result = script_pattern.sub(replace_script, html_str)
    result = link_pattern.sub(replace_link, result)

    return result
