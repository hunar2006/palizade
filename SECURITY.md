# Security Policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (https://github.com/hunar2006/palizade/security/advisories/new). If that option is not available, open an issue that asks for a private contact, without any details of the problem.

Useful details: the Palizade version (`palizade --version`), your client (Claude Desktop, Claude Code, Cursor, Codex), the policy preset, and the smallest set of MCP messages or a `palizade audit --json` excerpt that shows the issue. Remove secrets and personal data first.

You can expect an acknowledgement within a week. Fixes are released as patch versions and noted in `CHANGELOG.md`.

## Supported versions

Only the latest published minor version receives security fixes.

## Scope

In scope: a way to get untrusted content to drive a blocked action without approval, bypasses of taint, destination or secret checks, crashes or memory exhaustion of the proxy caused by a server or client, approval inbox or listener authentication problems, and audit log tampering.

Out of scope: the limits listed under "What Palizade Does Not Protect" in the README, such as native tools without hooks installed, a compromised machine or client, and links or images rendered by the client itself.
