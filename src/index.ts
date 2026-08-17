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

// Summarize OSV vulnerabilities
function summarizeOsvVulns(vulns: OsvVuln[] | undefined) {
  if (!vulns || vulns.length === 0) {
    return { vulnerable: false, count: 0, vulnerabilities: [] };
  }
  const summarized = vulns.map((v) => {
    const fixedVersions = new Set<string>();
    for (const affected of v.affected ?? []) {
      for (const range of affected.ranges ?? []) {
        for (const event of range.events ?? []) {
          if (event.fixed) fixedVersions.add(event.fixed);
        }
      }
    }
    return {
      id: v.id,
      aliases: v.aliases ?? [],
      summary: v.summary ?? v.details?.slice(0, 200) ?? "No summary available",
      severity: v.severity?.[0]?.score ?? "unknown",
      fixed_in: [...fixedVersions],
    };
  });
  return { vulnerable: true, count: summarized.length, vulnerabilities: summarized };
}

// MCP Functions
// NVD CVE Lookup
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

// Check package vulnerabilities using OSV.dev
server.registerTool(
  "check_package",
  {
    title: "Check Package",
    description: "Query OSV.dev for known vulnerabilities in a specific package + version. Requires the ecosystem (npm, PyPI, etc.) to disambiguate packages with the same name across registries.",
    inputSchema: {
      package_name: z.string(),
      package_version: z.string(),
      ecosystem: ecosystemEnum,
    },
  },
  async ({ package_name, package_version, ecosystem }) => {
    const response = await fetch(osvApiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: package_name, ecosystem },
        version: package_version,
      }),
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch package data: ${response.statusText}`);
    }
    const data = await response.json();
    const summary = summarizeOsvVulns(data.vulns);
    return { content: [{ type: "text", text: JSON.stringify(summary, null, 2) }] };
  }
);

// Batch scan dependencies using OSV.dev
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
