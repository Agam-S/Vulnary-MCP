# Vulnary-MCP

A MCP (Model Context Protocol) server for open-source vulnerability intelligence. It can look up CVEs and check packages against known vulnerabilities, directly from an MCP-compatible AI assistant.

Combines [OSV.dev](https://osv.dev) (open-source package vulnerabilities) and [NVD](https://nvd.nist.gov) (CVE database) into a small set of MCP tools.

## Features

- 🔍 Look up a CVE by ID and get a parsed summary (description, severity, score, references) from NVD
- 📦 Check a specific package/version for known vulnerabilities via OSV.dev
- 📋 Batch-check a list of dependencies in one call
- 📄 Scan the raw contents of a package.json or requirements.txt file for known vulnerabilities
- 🧩 Works with any MCP-compatible client (Claude Desktop, Claude Code, LM Studio, etc.)


## Installation

```bash
git clone https://github.com/Agam-S/Vulnary-MCP
cd Vulnary-MCP
npm install
npm run build
```

## Usage

Add it to your MCP client's config, pointing at the built entry point:

```json
{
  "mcpServers": {
    "vulnary": {
      "command": "node",
      "args": ["/absolute/path/to/Vulnary-MCP/dist/index.js"]
    }
  }
}
```

Restart the client and the tools below should appear.

## Tools

| Tool | Description |
|---|---|
| `lookup_cve` | 	Fetch a parsed summary (description, severity, score, references) for a CVE ID from NVD |
| `check_package` | Query OSV.dev for known vulnerabilities in a specific package + version (requires ecosystem, e.g. npm, PyPI) |
| `scan_dependencies` | Batch-check a list of `{ name, version }` dependencies against OSV.dev for a given ecosystem |
| `scan_dependency_file` | Parse the raw contents of a `package.json` or `requirements.txt` file and batch-check every listed dependency against OSV.dev |


## Note: 
`scan_dependency_file` reads dependencies straight out of `package.json` (dependencies + devDependencies) or a `requirements.txt` with pinned == versions. It does not parse lockfiles (`package-lock.json`, `Pipfile.lock`, etc.) or unpinned/range version specifiers.


## Resources:
* [NVD API Guide](nvdGuide.md)
* [OSV API Guide](osvGuide.md)


## License
MIT License. See [LICENSE](LICENSE) for details.