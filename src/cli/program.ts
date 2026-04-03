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
    .version("0.1.0");

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
    .option("--check <checkId>", "Fix a specific check only")
    .action(fixCommand);

  program
    .command("explain <checkId>")
    .description("Show detailed explanation of a specific finding")
    .action(explainCommand);

  return program;
}

async function explainCommand(checkId: string): Promise<void> {
  const { getRegistry } = await import("../scanners/registry.js");
  const registry = getRegistry();
  const scanner = await registry.detectScanner();

  if (!scanner) {
    process.stderr.write("No supported agent detected.\n");
    process.exit(1);
  }

  const result = await scanner.scan({ verbose: false });
  const finding = result.findings.find((f) => f.checkId === checkId);

  if (!finding) {
    process.stderr.write(`No finding with checkId "${checkId}".\n`);
    process.stderr.write(
      "Run 'agentarmor scan' to see all findings and their checkIds.\n"
    );
    process.exit(1);
  }

  const out = process.stdout;
  out.write("\n");
  out.write(`  ${finding.title}\n`);
  out.write(`  Check ID: ${finding.checkId}\n`);
  out.write(`  Severity: ${finding.severity.toUpperCase()}\n`);
  out.write(`  Category: ${finding.category}\n`);
  if (finding.atlasId) {
    out.write(`  MITRE ATLAS: ${finding.atlasId}\n`);
  }
  out.write("\n");
  out.write(`  ${finding.detail}\n`);
  out.write("\n");
  out.write(`  Blast Radius:\n`);
  out.write(`  ${finding.blastRadius}\n`);
  if (finding.remediation) {
    out.write("\n");
    out.write(`  Fix:\n`);
    out.write(`  ${finding.remediation}\n`);
  }
  out.write("\n");
}
