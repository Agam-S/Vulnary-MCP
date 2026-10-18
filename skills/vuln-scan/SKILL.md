---
name: vuln-scan
description: Check a project's dependencies, a specific package version, or a CVE ID for known vulnerabilities using the Vulnary tools (OSV.dev and NVD). Use when the user asks "is this package safe", "scan my dependencies", "audit package.json / requirements.txt", "what is CVE-XXXX-YYYY", or wants a vulnerability report before upgrading or shipping.
---

# Vulnerability scan

Use the Vulnary MCP tools. Do not guess vulnerability data from memory; always call a tool.

## Pick the tool

| User has | Tool |
|---|---|
| A CVE ID (e.g. `CVE-2021-44228`) | `lookup_cve` |
| One package + version | `check_package` (needs `ecosystem`: npm, PyPI, crates.io, Go, Maven, RubyGems, NuGet) |
| A list of packages in one ecosystem | `scan_dependencies` |
| A `package.json` or `requirements.txt` in the project | Read the file, then pass its raw contents to `scan_dependency_file` |

For other manifests (Cargo.toml, go.mod, pom.xml, Gemfile, .csproj), read the file yourself, extract `{ name, version }` pairs and call `scan_dependencies` with the matching ecosystem.

## Limits to tell the user about

- `scan_dependency_file` strips a leading `^` or `~` and checks that version only. It does not read lockfiles, so the installed version may differ. If a lockfile exists, prefer extracting exact versions from it and calling `scan_dependencies`.
- `requirements.txt` lines without a pinned `==` version are skipped. Mention any you skipped.
- NVD rate-limits unauthenticated requests; if `lookup_cve` fails, wait and retry once.

## Report

1. One line: how many packages scanned, how many vulnerable.
2. A table of vulnerable packages only: package, current version, vulnerability IDs, severity, fixed in.
3. The upgrade to make for each one (lowest `fixed_in` version above the current one). If `fixed_in` is empty, say no fix is published yet.
4. Offer to apply the upgrades. Do not edit dependency files unless the user agrees.
