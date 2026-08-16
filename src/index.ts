import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";


const osvApiUrl = "https://api.osv.dev/v1/query";
const nvdApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";

const server = new McpServer({
  name: "Vulnary MCP",
  version: "1.0.0",
});

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
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
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
