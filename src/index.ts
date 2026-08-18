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
    description: "Batch-check a list of named dependencies (with versions) against OSV.dev.",
    inputSchema: {
      ecosystem: ecosystemEnum,
      dependencies: z.array(
        z.object({
          name: z.string(),
          version: z.string(),
        })
      ),
    },
  },
  async ({ ecosystem, dependencies }) => {
    const response = await fetch(osvBatchApiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: dependencies.map((dep) => ({
          version: dep.version,
          package: { name: dep.name, ecosystem },
        })),
      }),
    });
    if (!response.ok) {
      throw new Error(`OSV batch query failed: ${response.statusText}`);
    }
    const data = await response.json();
    const results = dependencies.map((dep, i) => ({
      package: dep.name,
      version: dep.version,
      ...summarizeOsvVulns(data.results?.[i]?.vulns),
    }));
    const vulnerableCount = results.filter((r) => r.vulnerable).length;
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { scanned: results.length, vulnerable_packages: vulnerableCount, results },
            null,
            2
          ),
        },
      ],
    };
  }
);

// Scan Dependencies By File
server.registerTool(
  "scan_dependency_file",
  {
    title: "Scan Dependency File",
    description:
      "Parse the raw contents of a package.json or requirements.txt file and check every listed dependency against OSV.dev.",
    inputSchema: {
      file_type: z.enum(["package.json", "requirements.txt"]),
      file_contents: z.string(),
    },
  },
  async ({ file_type, file_contents }) => {
    let dependencies: { name: string; version: string }[] = [];
    let ecosystem: string;

    if (file_type === "package.json") {
      ecosystem = "npm";
      const parsed = JSON.parse(file_contents);
      const deps = { ...parsed.dependencies, ...parsed.devDependencies };
      dependencies = Object.entries(deps).map(([name, version]) => ({
        name,
        version: String(version).replace(/^[\^~]/, ""),
      }));
    } else {
      ecosystem = "PyPI";
      dependencies = file_contents
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"))
        .map((line) => {
          const match = line.match(/^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.-]+)/);
          return match ? { name: match[1], version: match[2] } : null;
        })
        .filter((d): d is { name: string; version: string } => d !== null);
    }

    if (dependencies.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "No pinned dependencies with parseable versions were found in the file.",
          },
        ],
      };
    }

    const response = await fetch(osvBatchApiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: dependencies.map((dep) => ({
          version: dep.version,
          package: { name: dep.name, ecosystem },
        })),
      }),
    });
    if (!response.ok) {
      throw new Error(`OSV batch query failed: ${response.statusText}`);
    }
    const data = await response.json();
    const results = dependencies.map((dep, i) => ({
      package: dep.name,
      version: dep.version,
      ...summarizeOsvVulns(data.results?.[i]?.vulns),
    }));
    const vulnerableCount = results.filter((r) => r.vulnerable).length;
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { file_type, ecosystem, scanned: results.length, vulnerable_packages: vulnerableCount, results },
            null,
            2
          ),
        },
      ],
    };
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
