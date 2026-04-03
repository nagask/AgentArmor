import { getRegistry } from "../scanners/registry.js";

export async function fixCommand(opts: {
  dryRun?: boolean;
}): Promise<void> {
  const registry = getRegistry();
  const scanner = await registry.detectScanner();

  if (!scanner) {
    process.stderr.write("No supported agent detected.\n");
    process.exit(1);
    return;
  }

  if (!scanner.fix) {
    process.stderr.write(`${scanner.label} scanner does not support auto-fix yet.\n`);
    process.exit(1);
    return;
  }

  // Note: OpenClaw's --fix is all-or-nothing. Per-check filtering requires
  // upstream support. For now we apply all safe fixes together.
  const result = await scanner.scan({ verbose: false });
  const fixResults = await scanner.fix(result.findings, opts.dryRun ?? false);

  for (const r of fixResults) {
    const prefix = opts.dryRun ? "[DRY RUN]" : r.applied ? "[FIXED]" : "[SKIP]";
    process.stdout.write(`  ${prefix} ${r.description}\n`);
    if (r.error) {
      process.stderr.write(`    Error: ${r.error}\n`);
    }
  }

  if (!opts.dryRun) {
    const applied = fixResults.filter((r) => r.applied).length;
    process.stdout.write("\n");
    process.stdout.write(`  ${applied} fix(es) applied. Run 'agentarmor scan' to see your new score.\n`);
  }
}
