"""Content Security Policy (CSP) Level 3 Builder and Multi-Platform Exporters.

Provides zero-dependency CSP construction with cryptographically secure nonces,
strict-dynamic propagation, hash authorization, fallback policies, reporting endpoints,
and native exporters for Nginx, Apache, Cloudflare Workers, Netlify, Vercel, and Next.js.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# Standard CSP Keywords that must be enclosed in single quotes
_CSP_KEYWORDS: Set[str] = {
    "self",
    "unsafe-inline",
    "unsafe-eval",
    "strict-dynamic",
    "none",
    "unsafe-hashes",
    "report-sample",
    "wasm-unsafe-eval",
    "inline-speculation-rules",
    "script",
}

# Boolean / Flag directives that take no source expressions
_BOOLEAN_DIRECTIVES: Set[str] = {
    "upgrade-insecure-requests",
    "block-all-mixed-content",
}


def _format_source(source: str) -> str:
    """Format a source token according to CSP specifications."""
    s = source.strip()
    if not s:
        return s

    # Already quoted
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        return s

    # Standard keyword without quotes
    if s.lower() in _CSP_KEYWORDS:
        return f"'{s.lower()}'"

    # Nonce without quotes: nonce-xyz -> 'nonce-xyz'
    if s.lower().startswith("nonce-"):
        return f"'{s}'"

    # Hashes without quotes: sha256-xyz, sha384-xyz, sha512-xyz -> 'sha256-xyz'
    lower_s = s.lower()
    if lower_s.startswith(("sha256-", "sha384-", "sha512-")):
        return f"'{s}'"

    return s


class CSPBuilder:
    """Builder for CSP Level 3 security headers and platform configurations."""

    def __init__(
        self,
        default_src: Optional[Sequence[str]] = None,
        script_src: Optional[Sequence[str]] = None,
        script_src_elem: Optional[Sequence[str]] = None,
        script_src_attr: Optional[Sequence[str]] = None,
        style_src: Optional[Sequence[str]] = None,
        style_src_elem: Optional[Sequence[str]] = None,
        style_src_attr: Optional[Sequence[str]] = None,
        img_src: Optional[Sequence[str]] = None,
        font_src: Optional[Sequence[str]] = None,
        connect_src: Optional[Sequence[str]] = None,
        media_src: Optional[Sequence[str]] = None,
        object_src: Optional[Sequence[str]] = None,
        frame_src: Optional[Sequence[str]] = None,
        frame_ancestors: Optional[Sequence[str]] = None,
        form_action: Optional[Sequence[str]] = None,
        base_uri: Optional[Sequence[str]] = None,
        worker_src: Optional[Sequence[str]] = None,
        child_src: Optional[Sequence[str]] = None,
        manifest_src: Optional[Sequence[str]] = None,
        report_uri: Optional[Union[str, Sequence[str]]] = None,
        report_to: Optional[str] = None,
        upgrade_insecure_requests: bool = False,
        block_all_mixed_content: bool = False,
        require_trusted_types_for: Optional[str] = None,
        trusted_types: Optional[Sequence[str]] = None,
        sandbox: Optional[Sequence[str]] = None,
        **extra_directives: Any,
    ) -> None:
        self._directives: Dict[str, List[str]] = {}
        self._last_nonce: Optional[str] = None

        if default_src is not None:
            self.set_directive("default-src", default_src)
        if script_src is not None:
            self.set_directive("script-src", script_src)
        if script_src_elem is not None:
            self.set_directive("script-src-elem", script_src_elem)
        if script_src_attr is not None:
            self.set_directive("script-src-attr", script_src_attr)
        if style_src is not None:
            self.set_directive("style-src", style_src)
        if style_src_elem is not None:
            self.set_directive("style-src-elem", style_src_elem)
        if style_src_attr is not None:
            self.set_directive("style-src-attr", style_src_attr)
        if img_src is not None:
            self.set_directive("img-src", img_src)
        if font_src is not None:
            self.set_directive("font-src", font_src)
        if connect_src is not None:
            self.set_directive("connect-src", connect_src)
        if media_src is not None:
            self.set_directive("media-src", media_src)
        if object_src is not None:
            self.set_directive("object-src", object_src)
        if frame_src is not None:
            self.set_directive("frame-src", frame_src)
        if frame_ancestors is not None:
            self.set_directive("frame-ancestors", frame_ancestors)
        if form_action is not None:
            self.set_directive("form-action", form_action)
        if base_uri is not None:
            self.set_directive("base-uri", base_uri)
        if worker_src is not None:
            self.set_directive("worker-src", worker_src)
        if child_src is not None:
            self.set_directive("child-src", child_src)
        if manifest_src is not None:
            self.set_directive("manifest-src", manifest_src)

        if report_uri is not None:
            uris = [report_uri] if isinstance(report_uri, str) else list(report_uri)
            self.set_directive("report-uri", uris)

        if report_to is not None:
            self.set_directive("report-to", [report_to])

        if upgrade_insecure_requests:
            self.set_directive("upgrade-insecure-requests", [])

        if block_all_mixed_content:
            self.set_directive("block-all-mixed-content", [])

        if require_trusted_types_for is not None:
            formatted_tt = _format_source(require_trusted_types_for)
            self.set_directive("require-trusted-types-for", [formatted_tt])

        if trusted_types is not None:
            self.set_directive("trusted-types", trusted_types)

        if sandbox is not None:
            self.set_directive("sandbox", sandbox)

        for key, val in extra_directives.items():
            dir_name = key.replace("_", "-")
            if isinstance(val, (list, tuple)):
                self.set_directive(dir_name, val)
            elif isinstance(val, str):
                self.set_directive(dir_name, [val])
            elif val is True:
                self.set_directive(dir_name, [])

    @property
    def last_nonce(self) -> Optional[str]:
        """Return the most recently generated or assigned nonce."""
        return self._last_nonce

    @staticmethod
    def generate_nonce(num_bytes: int = 16) -> str:
        """Generate a cryptographically secure base64-encoded nonce."""
        random_bytes = secrets.token_bytes(num_bytes)
        return base64.b64encode(random_bytes).decode("ascii")

    def add_nonce(
        self,
        nonce: Optional[str] = None,
        target_directives: Sequence[str] = ("script-src", "style-src"),
    ) -> str:
        """Add a cryptographic nonce to target directives and return the nonce value.

        Args:
            nonce: Optional specific nonce string. If None, generates a secure 16-byte nonce.
            target_directives: Directives to add the nonce to (default: script-src, style-src).

        Returns:
            The raw nonce string (without 'nonce-' prefix).
        """
        active_nonce = nonce if nonce is not None else self.generate_nonce()
        self._last_nonce = active_nonce
        formatted_nonce = f"'nonce-{active_nonce}'"

        for directive in target_directives:
            norm_directive = directive.strip().lower()
            current = self._directives.get(norm_directive, [])
            if formatted_nonce not in current:
                self.add_directive(norm_directive, formatted_nonce)

        return active_nonce

    def add_script_hash(
        self,
        content: Union[str, bytes],
        algorithm: str = "sha256",
        target_directive: str = "script-src",
    ) -> str:
        """Compute the cryptographic hash of inline script content and add it to script-src.

        Args:
            content: Raw string or bytes of the script content.
            algorithm: Hash algorithm: 'sha256', 'sha384', or 'sha512'.
            target_directive: Directive to add the hash to (default: script-src).

        Returns:
            Formatted hash token string, e.g. "'sha256-abc...'".
        """
        alg = algorithm.lower().strip()
        if alg not in ("sha256", "sha384", "sha512"):
            raise ValueError(f"Unsupported CSP hash algorithm '{algorithm}'. Must be sha256, sha384, or sha512.")

        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
        digest = hashlib.new(alg, raw_bytes).digest()
        b64_digest = base64.b64encode(digest).decode("ascii")
        hash_token = f"'{alg}-{b64_digest}'"

        self.add_directive(target_directive, hash_token)
        return hash_token

    def add_style_hash(
        self,
        content: Union[str, bytes],
        algorithm: str = "sha256",
        target_directive: str = "style-src",
    ) -> str:
        """Compute the cryptographic hash of inline style content and add it to style-src.

        Args:
            content: Raw string or bytes of the stylesheet content.
            algorithm: Hash algorithm: 'sha256', 'sha384', or 'sha512'.
            target_directive: Directive to add the hash to (default: style-src).

        Returns:
            Formatted hash token string, e.g. "'sha256-abc...'".
        """
        return self.add_script_hash(content, algorithm=algorithm, target_directive=target_directive)

    def enable_strict_csp(
        self,
        nonce: Optional[str] = None,
        enable_strict_dynamic: bool = True,
        unsafe_inline_fallback: bool = True,
        https_fallback: bool = True,
        object_none: bool = True,
        base_uri_none: bool = True,
    ) -> "CSPBuilder":
        """Configure standard CSP Level 3 Strict CSP pattern.

        - Automatically assigns a cryptographically secure nonce to script-src.
        - Enables 'strict-dynamic' for transitive script execution.
        - Adds 'unsafe-inline' and 'https:' as fallbacks for legacy browsers.
        - Restricts object-src to 'none' and base-uri to 'none'.

        Returns:
            Self instance for method chaining.
        """
        active_nonce = self.add_nonce(nonce=nonce, target_directives=("script-src",))
        formatted_nonce = f"'nonce-{active_nonce}'"

        script_sources: List[str] = [formatted_nonce]

        if enable_strict_dynamic:
            script_sources.append("'strict-dynamic'")

        if unsafe_inline_fallback:
            script_sources.append("'unsafe-inline'")

        if https_fallback:
            script_sources.append("https:")
            script_sources.append("http:")

        self.set_directive("script-src", script_sources)

        if object_none:
            self.set_directive("object-src", ["'none'"])

        if base_uri_none:
            self.set_directive("base-uri", ["'none'"])

        return self

    def add_directive(self, directive_name: str, *sources: str) -> "CSPBuilder":
        """Append one or more sources to a directive without duplicates.

        Args:
            directive_name: Name of the CSP directive (e.g. 'script-src').
            *sources: Source expressions to add.

        Returns:
            Self instance for method chaining.
        """
        norm_name = directive_name.strip().lower()
        if norm_name not in self._directives:
            self._directives[norm_name] = []

        for src in sources:
            fmt_src = _format_source(src)
            if fmt_src and fmt_src not in self._directives[norm_name]:
                self._directives[norm_name].append(fmt_src)

        return self

    def set_directive(self, directive_name: str, sources: Sequence[str]) -> "CSPBuilder":
        """Replace all source expressions for a directive.

        Args:
            directive_name: Name of the CSP directive.
            sources: Sequence of source expressions.

        Returns:
            Self instance for method chaining.
        """
        norm_name = directive_name.strip().lower()
        formatted_list: List[str] = []
        for src in sources:
            fmt_src = _format_source(src)
            if fmt_src and fmt_src not in formatted_list:
                formatted_list.append(fmt_src)
        self._directives[norm_name] = formatted_list
        return self

    def remove_directive(self, directive_name: str) -> "CSPBuilder":
        """Remove a directive completely from the policy.

        Args:
            directive_name: Name of the directive to remove.

        Returns:
            Self instance for method chaining.
        """
        norm_name = directive_name.strip().lower()
        self._directives.pop(norm_name, None)
        return self

    def get_directive(self, directive_name: str) -> List[str]:
        """Get the current source list for a directive."""
        norm_name = directive_name.strip().lower()
        return list(self._directives.get(norm_name, []))

    def has_directive(self, directive_name: str) -> bool:
        """Check if a directive is defined."""
        norm_name = directive_name.strip().lower()
        return norm_name in self._directives

    def copy(self) -> "CSPBuilder":
        """Create an independent deep copy of the builder."""
        cloned = CSPBuilder()
        cloned._directives = copy.deepcopy(self._directives)
        cloned._last_nonce = self._last_nonce
        return cloned

    def build(self) -> str:
        """Compile the CSP directives into a standard policy string.

        Returns:
            Semicolon-separated CSP policy string.
        """
        parts: List[str] = []
        for name, sources in self._directives.items():
            if name in _BOOLEAN_DIRECTIVES:
                parts.append(name)
            elif sources:
                parts.append(f"{name} {' '.join(sources)}")
            elif name == "sandbox":
                # sandbox without parameters is valid
                parts.append(name)
            else:
                parts.append(f"{name}")

        return "; ".join(parts)

    def to_header(
        self,
        report_only: bool = False,
        include_header_name: bool = False,
    ) -> str:
        """Export as an HTTP response header.

        Args:
            report_only: Whether to use Content-Security-Policy-Report-Only.
            include_header_name: If True, prefixes 'Content-Security-Policy: '.

        Returns:
            Header string.
        """
        header_name = "Content-Security-Policy-Report-Only" if report_only else "Content-Security-Policy"
        policy_str = self.build()
        if include_header_name:
            return f"{header_name}: {policy_str}"
        return policy_str

    def to_meta_tag(self, report_only: bool = False) -> str:
        """Export as an HTML <meta> tag.

        Note: Report-Only mode is not supported by browsers via <meta>, but will be labeled.
        """
        header_name = "Content-Security-Policy-Report-Only" if report_only else "Content-Security-Policy"
        policy_str = self.build()
        return f'<meta http-equiv="{header_name}" content="{policy_str}">'

    def to_nginx_directive(
        self,
        header_name: Optional[str] = None,
        always: bool = True,
    ) -> str:
        """Export as an Nginx configuration directive.

        Args:
            header_name: Custom header name (defaults to Content-Security-Policy).
            always: Appends 'always' keyword to apply header to error responses.

        Returns:
            Nginx configuration string snippet.
        """
        h_name = header_name or "Content-Security-Policy"
        policy_str = self.build()
        always_flag = " always" if always else ""
        return f'add_header {h_name} "{policy_str}"{always_flag};'

    def to_apache_directive(
        self,
        header_name: Optional[str] = None,
    ) -> str:
        """Export as an Apache HTTP Server (.htaccess / httpd.conf) directive.

        Returns:
            Apache configuration string snippet with mod_headers guard.
        """
        h_name = header_name or "Content-Security-Policy"
        policy_str = self.build()
        return (
            "<IfModule mod_headers.c>\n"
            f'    Header set {h_name} "{policy_str}"\n'
            "</IfModule>"
        )

    def to_cloudflare_workers(
        self,
        nonce_var: str = "nonce",
    ) -> str:
        """Export as a Cloudflare Workers JavaScript edge-handler snippet with dynamic nonces.

        Args:
            nonce_var: Variable name for the generated nonce.

        Returns:
            JavaScript Cloudflare Worker code snippet.
        """
        # Create a dynamic CSP string template where the nonce placeholder is injected
        raw_policy = self.build()
        # Replace the concrete nonce in the string with dynamic template literal ${nonce}
        if self._last_nonce and f"nonce-{self._last_nonce}" in raw_policy:
            js_csp = raw_policy.replace(f"nonce-{self._last_nonce}", f"nonce-${{{nonce_var}}}")
        else:
            js_csp = raw_policy

        return (
            "export default {\n"
            "  async fetch(request, env, ctx) {\n"
            f"    const {nonce_var} = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));\n"
            f"    const cspHeader = `{js_csp}`;\n"
            "\n"
            "    const response = await fetch(request);\n"
            "    const newHeaders = new Headers(response.headers);\n"
            '    newHeaders.set("Content-Security-Policy", cspHeader);\n'
            f'    newHeaders.set("x-nonce", {nonce_var});\n'
            "\n"
            "    return new Response(response.body, {\n"
            "      status: response.status,\n"
            "      statusText: response.statusText,\n"
            "      headers: newHeaders,\n"
            "    });\n"
            "  },\n"
            "};"
        )

    def to_netlify_headers(self, path: str = "/*") -> str:
        """Export as a Netlify `_headers` configuration snippet.

        Args:
            path: Route glob pattern to apply headers to (default: /*).

        Returns:
            Netlify _headers file formatted text.
        """
        policy_str = self.build()
        return f"{path}\n  Content-Security-Policy: {policy_str}\n  X-Content-Type-Options: nosniff"

    def to_vercel_json(self, source: str = "/(.*)") -> Dict[str, Any]:
        """Export as a Vercel `vercel.json` headers configuration dictionary.

        Args:
            source: Route regex to apply headers to (default: /(.*)).

        Returns:
            Dictionary matching Vercel JSON specification.
        """
        policy_str = self.build()
        return {
            "headers": [
                {
                    "source": source,
                    "headers": [
                        {
                            "key": "Content-Security-Policy",
                            "value": policy_str,
                        },
                        {
                            "key": "X-Content-Type-Options",
                            "value": "nosniff",
                        },
                    ],
                }
            ]
        }

    def to_vercel_json_str(self, source: str = "/(.*)", indent: int = 2) -> str:
        """Export as a formatted JSON string for `vercel.json`."""
        return json.dumps(self.to_vercel_json(source=source), indent=indent)

    def to_nextjs_middleware(self) -> str:
        """Export as a production-grade Next.js 14/15 `middleware.ts` with crypto nonce generation.

        Generates request-level CSP header injection with `x-nonce` passing for React Server Components.

        Returns:
            TypeScript Next.js middleware file string.
        """
        raw_policy = self.build()
        if self._last_nonce and f"nonce-{self._last_nonce}" in raw_policy:
            ts_csp = raw_policy.replace(f"nonce-{self._last_nonce}", "nonce-${nonce}")
        else:
            ts_csp = raw_policy

        return (
            "import { NextRequest, NextResponse } from 'next/server';\n"
            "\n"
            "export function middleware(request: NextRequest) {\n"
            "  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');\n"
            f"  const cspHeader = `{ts_csp}`;\n"
            "\n"
            "  const requestHeaders = new Headers(request.headers);\n"
            "  requestHeaders.set('x-nonce', nonce);\n"
            "  requestHeaders.set('Content-Security-Policy', cspHeader);\n"
            "\n"
            "  const response = NextResponse.next({\n"
            "    request: {\n"
            "      headers: requestHeaders,\n"
            "    },\n"
            "  });\n"
            "  response.headers.set('Content-Security-Policy', cspHeader);\n"
            "\n"
            "  return response;\n"
            "}\n"
            "\n"
            "export const config = {\n"
            "  matcher: [\n"
            "    {\n"
            "      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',\n"
            "      missing: [\n"
            "        { type: 'header', key: 'next-router-prefetch' },\n"
            "        { type: 'header', key: 'purpose', value: 'prefetch' },\n"
            "      ],\n"
            "    },\n"
            "  ],\n"
            "};\n"
        )
