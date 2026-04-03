import { Command } from "commander";
import { scanCommand } from "./scan.js";
import { fixCommand } from "./fix.js";

export function createProgram(): Command {
  const program = new Command();

  program
    .name("agentarmor")
    .description(
      "Security scanner for AI agents. Scans your agent installation, checks it against the official security documentation, and gives you a score out of 100."
    )
    .version("0.1.1");

  program
    .command("scan")
    .description("Scan your agent installation for security issues")
    .option("--deep", "Include runtime probes (requires running agent)")
    .option("--json", "Output results as JSON to stdout")
    .option("--verbose", "Show detailed progress and debug info")
    .option("--timeout <ms>", "CLI command timeout in milliseconds", "30000")
    .option(
      "--fail-below <score>",
      "Exit with code 2 if score is below this threshold"
    )
    .option("--category <categories...>", "Scan only specific categories")
    .action(scanCommand);

  program
    .command("fix")
    .description("Apply safe fixes for detected security issues")
    .option("--dry-run", "Show what would be fixed without applying changes")
    .action(fixCommand);

  program
    .command("explain <checkId>")
    .description("Show detailed explanation of a specific finding")
    .action(explainCommand);

  return program;
}

async function explainCommand(checkId: string): Promise<void> {
  // Use the enrichment map directly — no scan needed, instant response
  const { getEnrichment } = await import(
    "../scanners/openclaw/enrichment-map.js"
  );
  const { CATEGORY_LABELS } = await import("../core/types.js");

  const enrichment = getEnrichment(checkId);
  const isKnown = enrichment.blastRadius.includes("doesn't have detailed context") === false;

  const out = process.stdout;
  out.write("\n");
  out.write(`  Check ID: ${checkId}\n`);
  out.write(`  Category: ${CATEGORY_LABELS[enrichment.category]} (${enrichment.category})\n`);
  if (enrichment.atlasId) {
    out.write(`  MITRE ATLAS: ${enrichment.atlasId}\n`);
  }
  out.write("\n");
  out.write(`  Blast Radius:\n`);
  out.write(`  ${enrichment.blastRadius}\n`);
  if (!isKnown) {
    out.write("\n");
    out.write(`  This checkId is not in AgentArmor's enrichment map yet.\n`);
    out.write(`  Run 'openclaw security audit' for the raw finding details.\n`);
  }
  out.write("\n");
}
