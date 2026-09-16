# Model Context Protocol (MCP) Client Setup Guide

Web Security Guard features a built-in MCP server that enables AI coding assistants (Claude Desktop, Cursor AI, Cline, Roo Code, Zed, and Windsurf) to autonomously perform security audits, build CSP Level 3 policies, compute Subresource Integrity digests, and validate WCAG 2.2 color contrast.

---

## ⚡ Quick Configuration

### 1. Claude Desktop
Add to your Claude Desktop config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "web-security-guard": {
      "command": "uvx",
      "args": ["web-security-guard", "mcp"]
    }
  }
}
```

### 2. Cursor AI Editor
In Cursor settings -> **Features** -> **MCP Servers** -> **Add new MCP server**:
- **Name**: `web-security-guard`
- **Type**: `command`
- **Command**: `uvx web-security-guard mcp`

Or in `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "web-security-guard": {
      "command": "uvx",
      "args": ["web-security-guard", "mcp"]
    }
  }
}
```

### 3. Cline / Roo Code (VS Code)
In `cline_mcp_settings.json`:
```json
{
  "mcpServers": {
    "web-security-guard": {
      "command": "uvx",
      "args": ["web-security-guard", "mcp"],
      "disabled": false,
      "autoApprove": ["audit_url", "generate_csp", "calculate_sri", "calculate_contrast"]
    }
  }
}
```

### 4. Zed Editor
In `~/.config/zed/settings.json`:
```json
{
  "context_servers": {
    "web-security-guard": {
      "command": {
        "path": "uvx",
        "args": ["web-security-guard", "mcp"]
      }
    }
  }
}
```

---

## 🛠️ Available MCP Tools

| Tool | Purpose | Example Agent Prompt |
| :--- | :--- | :--- |
| `audit_url` | Full security audit of HTTP headers & cookies | *"Audit https://my-site.com and tell me what security headers I am missing."* |
| `generate_csp` | Formulates CSP Level 3 with nonces & exports | *"Generate a Next.js App Router CSP middleware with strict-dynamic."* |
| `calculate_sri` | Computes SHA-256/384/512 hashes | *"Generate an SRI hash and script tag for bootstrap 5.3.0 bundle."* |
| `calculate_contrast` | Tests WCAG 2.2 color contrast & color blindness | *"Check if #1a73e8 on #ffffff satisfies WCAG AAA contrast."* |
| `remediate_headers` | Exports hardened server configs | *"Give me a hardened nginx.conf to achieve an A+ security score."* |
