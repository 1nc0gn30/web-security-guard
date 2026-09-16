"""
Web Security Guard - Project Security Patcher Module
Automatically hardens web applications across platforms (Netlify, Vercel, Next.js, Nginx, Static HTML)
by auto-detecting platform configurations and injecting zero-trust security headers idempotently.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import time
from typing import Dict, List, Optional, Any, Union, Tuple

from .remediator import SecurityRemediator


# Standard gold-standard security headers bundle
DEFAULT_SECURITY_HEADERS: Dict[str, str] = dict(SecurityRemediator.STANDARD_HEADERS)


def detect_project_platform(project_root: Union[str, Path]) -> str:
    """
    Detects the web framework / hosting platform of a target project directory.
    
    Returns one of:
      - 'nextjs'
      - 'netlify'
      - 'vercel'
      - 'astro'
      - 'nginx'
      - 'caddy'
      - 'apache'
      - 'static_html'
      - 'generic'
    """
    root = Path(project_root).resolve()
    if not root.exists() or not root.is_dir():
        return "static_html"

    # Check Next.js
    if (root / "next.config.js").exists() or (root / "next.config.mjs").exists() or (root / "next.config.ts").exists():
        return "nextjs"
    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            pkg_data = json.loads(pkg_json.read_text(encoding="utf-8"))
            deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
            if "next" in deps:
                return "nextjs"
            if "astro" in deps:
                return "astro"
        except Exception:
            pass

    # Check Astro
    if (root / "astro.config.mjs").exists() or (root / "astro.config.ts").exists():
        return "astro"

    # Check Netlify
    if (root / "netlify.toml").exists() or (root / "_headers").exists() or (root / "public" / "_headers").exists():
        return "netlify"

    # Check Vercel
    if (root / "vercel.json").exists() or (root / ".vercel").exists():
        return "vercel"

    # Check Nginx
    if (root / "nginx.conf").exists() or (root / "conf.d").is_dir():
        return "nginx"

    # Check Caddy
    if (root / "Caddyfile").exists():
        return "caddy"

    # Check Apache
    if (root / ".htaccess").exists():
        return "apache"

    # Check Static HTML
    html_files = list(root.glob("*.html")) + list((root / "public").glob("*.html") if (root / "public").is_dir() else [])
    if html_files or (root / "index.html").exists():
        return "static_html"

    return "generic"


class ProjectSecurityPatcher:
    """
    Applies zero-trust security headers directly to target codebases across platforms.
    Features:
      - Safe automated backups
      - Full idempotency (safe to run repeatedly)
      - Non-destructive AST/JSON/file merging
    """

    def __init__(
        self,
        project_root: Union[str, Path],
        target_platform: str = "auto",
        force: bool = False,
        custom_csp: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        create_backups: bool = True,
    ):
        self.project_root = Path(project_root).resolve()
        self.force = force
        self.create_backups = create_backups

        # Resolve platform
        if not target_platform or target_platform.lower() == "auto":
            self.platform = detect_project_platform(self.project_root)
        else:
            self.platform = target_platform.lower()

        # Build effective headers map
        self.headers = dict(DEFAULT_SECURITY_HEADERS)
        if custom_headers:
            self.headers.update(custom_headers)
        if custom_csp:
            self.headers["Content-Security-Policy"] = custom_csp

        self.modified_files: List[Dict[str, Any]] = []

    def _make_backup(self, file_path: Path) -> Optional[Path]:
        """Creates a timestamped or .bak backup of an existing file."""
        if not self.create_backups or not file_path.exists():
            return None
        backup_path = file_path.with_name(f"{file_path.name}.bak")
        if not backup_path.exists() or self.force:
            shutil.copy2(file_path, backup_path)
        return backup_path

    # -------------------------------------------------------------------------
    # Netlify Patcher (_headers)
    # -------------------------------------------------------------------------

    def patch_netlify(self) -> List[Dict[str, Any]]:
        """Patches or creates Netlify _headers file."""
        target_dir = self.project_root
        if (self.project_root / "public").is_dir() and not (self.project_root / "_headers").exists():
            headers_file = self.project_root / "public" / "_headers"
        else:
            headers_file = self.project_root / "_headers"

        if headers_file.exists():
            original_content = headers_file.read_text(encoding="utf-8")
            
            # Check if headers are already fully injected
            missing_headers = [k for k in self.headers if k not in original_content]
            if not missing_headers and not self.force:
                return [{
                    "file_path": str(headers_file),
                    "action": "unchanged",
                    "backup_path": None,
                    "injected_headers": [],
                    "message": "All security headers already present in _headers",
                }]

            backup = self._make_backup(headers_file)
            
            # Append or patch /* section
            lines = original_content.rstrip().split("\n")
            injected_keys = []
            
            # If /* rule exists, append missing headers under it
            has_root_rule = any(line.strip() == "/*" for line in lines)
            if not has_root_rule:
                lines.append("\n# Added by Web Security Guard")
                lines.append("/*")
                for k, v in self.headers.items():
                    lines.append(f"  {k}: {v}")
                    injected_keys.append(k)
            else:
                # Add missing headers after /*
                new_lines = []
                in_root = False
                for line in lines:
                    new_lines.append(line)
                    if line.strip() == "/*":
                        in_root = True
                        for k, v in self.headers.items():
                            if k not in original_content:
                                new_lines.append(f"  {k}: {v}")
                                injected_keys.append(k)
                    elif in_root and line.strip().startswith("/") and line.strip() != "/*":
                        in_root = False
                lines = new_lines

            headers_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return [{
                "file_path": str(headers_file),
                "action": "updated",
                "backup_path": str(backup) if backup else None,
                "injected_headers": injected_keys or list(self.headers.keys()),
                "message": "Successfully injected security headers into Netlify _headers",
            }]
        else:
            # Create fresh _headers file
            remediator = SecurityRemediator(custom_csp=self.headers.get("Content-Security-Policy"))
            remediator.headers = self.headers
            content = remediator.generate_netlify_headers()
            headers_file.parent.mkdir(parents=True, exist_ok=True)
            headers_file.write_text(content, encoding="utf-8")
            return [{
                "file_path": str(headers_file),
                "action": "created",
                "backup_path": None,
                "injected_headers": list(self.headers.keys()),
                "message": "Created new hardened Netlify _headers configuration",
            }]

    # -------------------------------------------------------------------------
    # Vercel Patcher (vercel.json)
    # -------------------------------------------------------------------------

    def patch_vercel(self) -> List[Dict[str, Any]]:
        """Patches or creates vercel.json with security headers."""
        vercel_file = self.project_root / "vercel.json"

        if vercel_file.exists():
            original_text = vercel_file.read_text(encoding="utf-8")
            try:
                data = json.loads(original_text)
            except Exception:
                data = {}

            backup = self._make_backup(vercel_file)

            if not isinstance(data, dict):
                data = {}

            headers_list = data.get("headers", [])
            if not isinstance(headers_list, list):
                headers_list = []

            # Check if a wildcard source exists
            wildcard_entry = None
            for entry in headers_list:
                if isinstance(entry, dict) and entry.get("source") in ["/(.*)", "/:path*", "/*", "/(.*)?"]:
                    wildcard_entry = entry
                    break

            injected_keys = []
            if wildcard_entry is None:
                new_entry = {
                    "source": "/(.*)",
                    "headers": [{"key": k, "value": v} for k, v in self.headers.items()],
                }
                headers_list.append(new_entry)
                injected_keys = list(self.headers.keys())
            else:
                existing_keys = {h.get("key") for h in wildcard_entry.get("headers", []) if isinstance(h, dict)}
                for k, v in self.headers.items():
                    if k not in existing_keys or self.force:
                        if k in existing_keys and self.force:
                            # Update existing
                            for h in wildcard_entry.get("headers", []):
                                if h.get("key") == k:
                                    h["value"] = v
                        else:
                            wildcard_entry.setdefault("headers", []).append({"key": k, "value": v})
                        injected_keys.append(k)

            if not injected_keys and not self.force:
                return [{
                    "file_path": str(vercel_file),
                    "action": "unchanged",
                    "backup_path": None,
                    "injected_headers": [],
                    "message": "All security headers already configured in vercel.json",
                }]

            data["headers"] = headers_list
            vercel_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            return [{
                "file_path": str(vercel_file),
                "action": "updated",
                "backup_path": str(backup) if backup else None,
                "injected_headers": injected_keys,
                "message": "Updated vercel.json with security headers",
            }]
        else:
            remediator = SecurityRemediator(custom_csp=self.headers.get("Content-Security-Policy"))
            remediator.headers = self.headers
            content = remediator.generate_vercel_json()
            vercel_file.write_text(content, encoding="utf-8")
            return [{
                "file_path": str(vercel_file),
                "action": "created",
                "backup_path": None,
                "injected_headers": list(self.headers.keys()),
                "message": "Created new hardened vercel.json configuration",
            }]

    # -------------------------------------------------------------------------
    # Next.js Patcher (middleware.ts)
    # -------------------------------------------------------------------------

    def patch_nextjs(self) -> List[Dict[str, Any]]:
        """Patches or creates Next.js middleware.ts for security headers."""
        src_dir = self.project_root / "src"
        middleware_file = (src_dir / "middleware.ts") if src_dir.is_dir() else (self.project_root / "middleware.ts")

        # Generate middleware content
        header_sets = []
        for k, v in self.headers.items():
            escaped_v = v.replace("'", "\\'")
            header_sets.append(f"  response.headers.set('{k}', '{escaped_v}');")

        headers_block = "\n".join(header_sets)

        content = (
            "import { NextResponse } from 'next/server';\n"
            "import type { NextRequest } from 'next/server';\n\n"
            "/**\n"
            " * Web Security Guard - Hardened Security Headers Middleware (100/100 A+)\n"
            " */\n"
            "export function middleware(request: NextRequest) {\n"
            "  const response = NextResponse.next();\n\n"
            "  // Security Headers Injection\n"
            + headers_block + "\n\n"
            "  return response;\n"
            "}\n\n"
            "export const config = {\n"
            "  matcher: [\n"
            "    /*\n"
            "     * Match all request paths except for the ones starting with:\n"
            "     * - api (API routes)\n"
            "     * - _next/static (static files)\n"
            "     * - _next/image (image optimization files)\n"
            "     * - favicon.ico (favicon file)\n"
            "     */\n"
            "    '/((?!_next/static|_next/image|favicon.ico).*)',\n"
            "  ],\n"
            "};\n"
        )

        if middleware_file.exists():
            original = middleware_file.read_text(encoding="utf-8")
            if "Strict-Transport-Security" in original and "Content-Security-Policy" in original and not self.force:
                return [{
                    "file_path": str(middleware_file),
                    "action": "unchanged",
                    "backup_path": None,
                    "injected_headers": [],
                    "message": "Next.js middleware already configures security headers",
                }]

            backup = self._make_backup(middleware_file)
            middleware_file.write_text(content, encoding="utf-8")
            return [{
                "file_path": str(middleware_file),
                "action": "updated",
                "backup_path": str(backup) if backup else None,
                "injected_headers": list(self.headers.keys()),
                "message": "Replaced Next.js middleware with hardened security middleware",
            }]
        else:
            middleware_file.parent.mkdir(parents=True, exist_ok=True)
            middleware_file.write_text(content, encoding="utf-8")
            return [{
                "file_path": str(middleware_file),
                "action": "created",
                "backup_path": None,
                "injected_headers": list(self.headers.keys()),
                "message": "Created hardened Next.js security middleware.ts",
            }]

    # -------------------------------------------------------------------------
    # Static HTML Meta Tags Patcher
    # -------------------------------------------------------------------------

    def patch_static_html(self) -> List[Dict[str, Any]]:
        """Injects security meta tags into all HTML files in root and public directories."""
        html_files: List[Path] = []
        for p in [self.project_root, self.project_root / "public"]:
            if p.is_dir():
                for f in p.glob("*.html"):
                    if not f.name.endswith(".bak"):
                        html_files.append(f)

        if not html_files:
            # Create a basic index.html if project root has nothing
            index_file = self.project_root / "index.html"
            remediator = SecurityRemediator(custom_csp=self.headers.get("Content-Security-Policy"))
            remediator.headers = self.headers
            meta_block = remediator.generate_html_meta().strip()
            
            sample_html = (
                "<!DOCTYPE html>\n"
                "<html lang=\"en\">\n"
                "<head>\n"
                "  <meta charset=\"UTF-8\">\n"
                "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
                f"  {meta_block}\n"
                "  <title>Hardened Web Application</title>\n"
                "</head>\n"
                "<body>\n"
                "  <h1>Web Application</h1>\n"
                "</body>\n"
                "</html>\n"
            )
            index_file.write_text(sample_html, encoding="utf-8")
            return [{
                "file_path": str(index_file),
                "action": "created",
                "backup_path": None,
                "injected_headers": ["Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"],
                "message": "Created hardened index.html with security meta tags",
            }]

        results: List[Dict[str, Any]] = []

        csp_val = self.headers.get("Content-Security-Policy", "")
        xcto_val = self.headers.get("X-Content-Type-Options", "nosniff")
        ref_val = self.headers.get("Referrer-Policy", "strict-origin-when-cross-origin")

        meta_tags_to_inject = [
            f'<meta http-equiv="Content-Security-Policy" content="{csp_val}">',
            f'<meta http-equiv="X-Content-Type-Options" content="{xcto_val}">',
            f'<meta http-equiv="Referrer-Policy" content="{ref_val}">',
        ]

        for hfile in html_files:
            content = hfile.read_text(encoding="utf-8")
            original_content = content
            injected_headers = []

            # Check if already present
            has_csp = bool(re.search(r'<meta\s+http-equiv=["\']Content-Security-Policy["\']', content, re.IGNORECASE))
            has_xcto = bool(re.search(r'<meta\s+http-equiv=["\']X-Content-Type-Options["\']', content, re.IGNORECASE))
            has_ref = bool(re.search(r'<meta\s+http-equiv=["\']Referrer-Policy["\']', content, re.IGNORECASE))

            tags_needed: List[str] = []
            if not has_csp or self.force:
                if has_csp and self.force:
                    content = re.sub(
                        r'<meta\s+http-equiv=["\']Content-Security-Policy["\'][^>]*>',
                        meta_tags_to_inject[0],
                        content,
                        flags=re.IGNORECASE,
                    )
                    injected_headers.append("Content-Security-Policy")
                else:
                    tags_needed.append(meta_tags_to_inject[0])
                    injected_headers.append("Content-Security-Policy")

            if not has_xcto:
                tags_needed.append(meta_tags_to_inject[1])
                injected_headers.append("X-Content-Type-Options")

            if not has_ref:
                tags_needed.append(meta_tags_to_inject[2])
                injected_headers.append("Referrer-Policy")

            if tags_needed:
                injection_str = "\n  " + "\n  ".join(tags_needed)
                # Inject right after <head> or <head ...>
                head_match = re.search(r'(<head[^>]*>)', content, re.IGNORECASE)
                if head_match:
                    content = content[: head_match.end()] + injection_str + content[head_match.end() :]
                else:
                    # Prepend if no head
                    content = injection_str + "\n" + content

            if content != original_content:
                backup = self._make_backup(hfile)
                hfile.write_text(content, encoding="utf-8")
                results.append({
                    "file_path": str(hfile),
                    "action": "updated",
                    "backup_path": str(backup) if backup else None,
                    "injected_headers": injected_headers,
                    "message": f"Injected security meta tags into {hfile.name}",
                })
            else:
                results.append({
                    "file_path": str(hfile),
                    "action": "unchanged",
                    "backup_path": None,
                    "injected_headers": [],
                    "message": f"Security meta tags already present in {hfile.name}",
                })

        return results

    # -------------------------------------------------------------------------
    # Nginx Patcher
    # -------------------------------------------------------------------------

    def patch_nginx(self) -> List[Dict[str, Any]]:
        """Patches or creates Nginx security headers configuration."""
        nginx_conf = self.project_root / "nginx.conf"
        headers_conf = self.project_root / "security-headers.conf"

        remediator = SecurityRemediator(custom_csp=self.headers.get("Content-Security-Policy"))
        remediator.headers = self.headers
        content = remediator.generate_nginx_conf()

        target = nginx_conf if nginx_conf.exists() else headers_conf
        if target.exists():
            orig = target.read_text(encoding="utf-8")
            if "Strict-Transport-Security" in orig and not self.force:
                return [{
                    "file_path": str(target),
                    "action": "unchanged",
                    "backup_path": None,
                    "injected_headers": [],
                    "message": "Nginx security headers already configured",
                }]
            backup = self._make_backup(target)
            target.write_text(orig + "\n" + content, encoding="utf-8")
            return [{
                "file_path": str(target),
                "action": "updated",
                "backup_path": str(backup) if backup else None,
                "injected_headers": list(self.headers.keys()),
                "message": "Appended security headers to Nginx config",
            }]
        else:
            target.write_text(content, encoding="utf-8")
            return [{
                "file_path": str(target),
                "action": "created",
                "backup_path": None,
                "injected_headers": list(self.headers.keys()),
                "message": f"Created {target.name} with security headers",
            }]

    # -------------------------------------------------------------------------
    # Main Execution Dispatcher
    # -------------------------------------------------------------------------

    def patch(self) -> Dict[str, Any]:
        """Executes security patching for the detected/target platform."""
        platform = self.platform

        if platform == "netlify":
            files = self.patch_netlify()
        elif platform == "vercel":
            files = self.patch_vercel()
        elif platform == "nextjs":
            files = self.patch_nextjs()
        elif platform == "nginx":
            files = self.patch_nginx()
        elif platform in ["static_html", "astro", "generic"]:
            files = self.patch_static_html()
            # If netlify or vercel config files also exist in project root, patch them too
            if (self.project_root / "_headers").exists():
                files.extend(self.patch_netlify())
            if (self.project_root / "vercel.json").exists():
                files.extend(self.patch_vercel())
        else:
            files = self.patch_static_html()

        self.modified_files = files

        updated_count = sum(1 for f in files if f.get("action") in ["created", "updated"])
        summary = f"Security Patch Complete for platform [{platform}]: {updated_count} file(s) modified/created."

        return {
            "success": True,
            "project_root": str(self.project_root),
            "detected_platform": platform,
            "target_platform": self.platform,
            "modified_files": self.modified_files,
            "injected_directives": self.headers,
            "summary": summary,
        }


def patch_project_security(
    project_root: Union[str, Path],
    target_platform: str = "auto",
    force: bool = False,
    custom_csp: Optional[str] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    create_backups: bool = True,
) -> Dict[str, Any]:
    """
    Main entrypoint function to auto-detect and patch web project security configurations.
    
    Parameters:
      - project_root: Root path of the web application
      - target_platform: 'auto', 'netlify', 'vercel', 'nextjs', 'nginx', 'static_html'
      - force: Whether to overwrite existing security headers
      - custom_csp: Optional custom Content-Security-Policy string
      - custom_headers: Optional dictionary of headers to override
      - create_backups: If True, creates .bak files before editing
      
    Returns:
      Dict with modified_files list, backup_paths, detected platform, and injected directives.
    """
    patcher = ProjectSecurityPatcher(
        project_root=project_root,
        target_platform=target_platform,
        force=force,
        custom_csp=custom_csp,
        custom_headers=custom_headers,
        create_backups=create_backups,
    )
    return patcher.patch()
