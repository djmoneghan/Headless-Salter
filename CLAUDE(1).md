# CLAUDE.md — web_sterilizer

This file provides guidance for Claude Code (and other AI coding assistants) working in this repository. Read this before writing or modifying any code.

---

## What This Project Is

`web_sterilizer` is a **Model Context Protocol (MCP) server** that gives local AI agents the ability to fetch and read web content safely. Its defining purpose is defending against **prompt injection** — the risk that adversarial content on a fetched web page hijacks the agent's behavior.

It is a security-first tool. Correctness of retrieval is secondary to safety of output.

---

## Architecture Overview

```
Local Agent (LLM)
      │
      │  (tool call via MCP client)
      ▼
MCP Client (host: OpenClaw, Claude Desktop, custom framework)
      │
      │  (stdio subprocess)
      ▼
web_sterilizer.py  ←── sterilizer_config.json
      │
      │  (HTTP GET only)
      ▼
External Web
```

**Key design constraints:**
- **stdio transport only** — the server runs as a subprocess, not a network service
- **No JavaScript execution** — static HTTP fetching only
- **Stateless** — no caching, no cookies, no persistent state between calls
- **Fail closed** — any error in the sterilization pipeline withholds content; it does not pass through partial output

---

## Core Files

| File | Purpose |
|---|---|
| `web_sterilizer.py` | MCP server — entry point, tool definition, fetch + sterilize pipeline |
| `sterilizer_config.json` | Runtime configuration: allowlist, limits, pattern overrides |
| `patterns.json` | Injection detection regex patterns (loadable, not hardcoded) |
| `REQUIREMENTS.md` | Full functional and non-functional requirements |
| `tests/` | Unit tests for sterilization pipeline stages |

---

## Critical Constraints — Read Before Touching Any Code

### MUST NOT change without explicit human approval:
1. **The salt delimiter system** (FR-07, FR-08): The randomized `[FETCHED_CONTENT_START::<salt>]` / `[FETCHED_CONTENT_END::<salt>]` wrapper is the primary injection boundary. Do not simplify, remove, or make static.
2. **The SSRF blocklist** (FR-15): RFC 1918 private ranges and loopback MUST always be blocked. Do not add logic that bypasses this for "local testing."
3. **The allowlist default-deny behavior** (FR-14): If no allowlist is configured, the tool must reject all requests. Do not change the default to permissive.
4. **Fail-closed error handling** (NFR-07): If any sterilization stage throws an exception, the content MUST be withheld. Do not add catch-and-continue logic that passes through unsanitized content.
5. **No POST/mutation methods** (FR-02): The tool fetches only. Do not add support for form submission, PUT, DELETE, or any state-changing HTTP method.

### MUST flag and hold (do not silently resolve):
- Any change to the sterilization pipeline order defined in §3.3 of REQUIREMENTS.md
- Any change that reduces the information returned in the audit log
- Any dependency addition that introduces network-accessible services or persistent storage
- Any change to how the `purpose` parameter is handled (it must be logged, not used in retrieval logic)
- Any proposal to cache fetched content between requests

**If you identify a conflict between these constraints and a user request, state the conflict explicitly before proceeding. Do not silently work around it.**

---

## Sterilization Pipeline

The pipeline runs in strict order. Each stage is independently testable. Do not reorder without documenting the reason.

```
1. Validate URL (scheme, SSRF, allowlist)
2. Fetch with timeout + size limit
3. Strip raw HTML → plain text (trafilatura)
4. Remove hidden/invisible element content
5. Normalize whitespace + strip control characters
6. Pattern scan (injection_patterns list)
7. Instruction verb filter
8. Length truncation
9. Wrap in salt delimiters
10. Append audit log
```

Each stage should be a discrete function. Do not merge stages.

---

## Configuration Reference

`sterilizer_config.json` controls runtime behavior without code changes:

```json
{
  "allowed_domains": ["example.com", "docs.python.org"],
  "max_redirects": 3,
  "timeout_seconds": 10,
  "max_response_bytes": 2097152,
  "max_output_chars": 8000,
  "pattern_file": "patterns.json",
  "verbose_logging": false
}
```

**`allowed_domains` is required.** If absent or empty, all requests MUST be rejected.

---

## MCP Tool Schema

The tool exposes three parameters to the MCP client:

```python
@mcp.tool()
def fetch_web_content(
    url: str,              # Required. The URL to fetch.
    purpose: str = "",     # Optional. Agent's stated reason for fetch. Logged only.
    allow_override: bool = False  # Reserved. Currently ignored. Do not implement logic for this yet.
) -> dict:
```

The return value is always a dict with:
```python
{
    "success": bool,
    "content": str,          # Salt-delimited sterilized text, or empty on failure
    "source_url": str,       # Final URL after redirects
    "fetch_timestamp": str,  # ISO 8601
    "salt_token": str,       # The salt used in this request's delimiters
    "injection_warning": bool,
    "audit_log": dict,       # Per-stage sterilization summary
    "error": str | None      # Error message if success=False
}
```

---

## Testing Requirements

Before submitting any change to the sterilization pipeline, tests MUST cover:

- [ ] Injection patterns are detected and flagged (not silently dropped)
- [ ] Content outside salt delimiters is not present in output
- [ ] SSRF: private IPs (10.x, 192.168.x, 127.x) are rejected
- [ ] Allowlist: domains not on list are rejected; empty allowlist rejects all
- [ ] Redirect depth > max is aborted
- [ ] Response > max bytes is truncated before parsing
- [ ] Exception in any pipeline stage returns `success=False` with no content leakage
- [ ] Salt tokens are unique across consecutive calls

Run tests with: `pytest tests/ -v`

---

## Dependency Policy

Approved dependencies (do not add others without discussion):
- `fastmcp` — MCP server framework
- `trafilatura` — HTML-to-text extraction
- `requests` — HTTP client (or `httpx` if async is needed)
- `pytest` — testing only

**Do not add:**
- Browser automation libraries (Playwright, Selenium, Puppeteer) — out of scope for this version
- Caching libraries (Redis, diskcache, etc.) — violates NFR-03
- Any library that opens a network-accessible port

---

## Threat Model Summary (for context)

The adversary is a web page that has been crafted to manipulate an AI agent reading its content. Attack vectors include visible text, HTML comments, hidden elements, and meta tags. The goal of `web_sterilizer` is to return **data** to the agent, never **instructions** — no matter what the page contains.

When in doubt: **withhold and report**, do not pass through.

---

## Related Documents

- `REQUIREMENTS.md` — Full specification with MoSCoW-style requirements
- `patterns.json` — Default injection detection patterns
- `CHANGELOG.md` — Version history (create when first release is tagged)

---

*This CLAUDE.md is authoritative for AI coding assistants working in this repo. Human maintainer retains final authority on all security-relevant decisions. Flag, don't fix, when constraints conflict.*
