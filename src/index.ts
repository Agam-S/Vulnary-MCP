import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// API URLs
const osvApiUrl = "https://api.osv.dev/v1/query";
const osvBatchApiUrl = "https://api.osv.dev/v1/querybatch";
const nvdApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const server = new McpServer({
  name: "Vulnary MCP",
  version: "1.1.0",
});

// Helpers
const ecosystemEnum = z
  .enum(["npm", "PyPI", "crates.io", "Go", "Maven", "RubyGems", "NuGet"])
  .describe("Package ecosystem OSV.dev should search in");

  
interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: { type: string; score: string }[];
  affected?: { ranges?: { events?: { fixed?: string }[] }[] }[];
  aliases?: string[];
}

// MCP Functions
server.registerTool(
  "lookup_cve",
  {
    title: "Lookup CVE",
    description: "Fetch details, severity, and references for a CVE ID from NVD",
    inputSchema: { cve_id: z.string() },
  },
  async ({ cve_id }) => {
    const response = await fetch(`${nvdApiUrl}?cveId=${cve_id}`);
    if (!response.ok) {
      throw new Error(`Failed to fetch CVE data: ${response.statusText}`);
    }
    const data = await response.json();
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) {
      return { content: [{ type: "text", text: `No data found for ${cve_id}` }] };
    }
    const summary = {
      id: vuln.id,
      description: vuln.descriptions?.find((d: any) => d.lang === "en")?.value,
      severity:
        vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
        vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
        vuln.metrics?.cvssMetricV2?.[0]?.baseSeverity ??
        "unknown",
      score:
        vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
        vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ??
        vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ??
        null,
      published: vuln.published,
      references: (vuln.references ?? []).slice(0, 5).map((r: any) => r.url),
    };
    return { content: [{ type: "text", text: JSON.stringify(summary, null, 2) }] };
  }
);

server.registerTool(
  "check_package",
  {
    title: "Check Package",
    description: "Query OSV.dev for known vulnerabilities in a specific package + version",
    inputSchema: {
      package_name: z.string(),
      package_version: z.string(),
      ecosystem: ecosystemEnum,
    },
  },
  async ({ package_name, package_version }) => {
    const response = await fetch(osvApiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: package_name },
        version: package_version,
      }),
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch package data: ${response.statusText}`);
    }
    const data = await response.json();
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.registerTool(
  "scan_dependencies",
  {
    title: "Scan Dependencies",
    description: "Batch-check a list of dependencies against OSV.dev",
    inputSchema: {
      dependencies: z.array(
        z.object({
          name: z.string(),
          version: z.string(),
        })
      ),
    },
  },
  async ({ dependencies }) => {
    const results = [];
    for (const dep of dependencies) {
      const response = await fetch(osvApiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          package: { name: dep.name },
          version: dep.version,
        }),
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch package data for ${dep.name}: ${response.statusText}`);
      }
      const data = await response.json();
      results.push({ package: dep, vulnerabilities: data });
    }
    return { content: [{ type: "text", text: JSON.stringify(results, null, 2) }] };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error: Error) => {
  console.error("Failed to start Vulnary MCP server:", error);
  process.exit(1);
});
