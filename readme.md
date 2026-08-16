# Vulnary-MCP

An MCP (Model Context Protocol) server for open-source vulnerability intelligence - look up CVEs and check packages against known vulnerabilities, directly from an MCP-compatible AI assistant.

Combines [OSV.dev](https://osv.dev) (open-source package vulnerabilities) and [NVD](https://nvd.nist.gov) (CVE database) into a small set of MCP tools.

## Features

- 🔍 Look up a CVE by ID and get raw NVD data back
- 📦 Check a specific package/version for known vulnerabilities via OSV.dev
- 📋 Batch-check a list of dependencies in one call
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
| `lookup_cve` | Fetch raw CVE data from NVD by CVE ID |
| `check_package` | Query OSV.dev for known vulnerabilities in a specific package + version |
| `scan_dependencies` | Batch-check a list of `{ name, version }` dependencies against OSV.dev |


## License
MIT License. See [LICENSE](LICENSE) for details.