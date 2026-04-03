import type { ScanOptions, CheckCategory } from "../core/types.js";
import { getRegistry } from "../scanners/registry.js";
import { renderTerminal, renderJson } from "../core/reporter.js";

export async function scanCommand(opts: {
  deep?: boolean;
  json?: boolean;
  verbose?: boolean;
  timeout?: string;
  failBelow?: string;
  category?: string[];
}): Promise<void> {
  const registry = getRegistry();
  const scanner = await registry.detectScanner();

  if (!scanner) {
    process.stderr.write("No supported agent detected.\n");
    process.stderr.write(
      "AgentArmor currently supports: OpenClaw. Is it installed?\n"
    );
    process.exit(1);
  }

  const options: ScanOptions = {
    deep: opts.deep,
    json: opts.json,
    verbose: opts.verbose,
    timeout: opts.timeout ? parseInt(opts.timeout, 10) : 30_000,
    failBelow: opts.failBelow ? parseInt(opts.failBelow, 10) : undefined,
    categories: opts.category as CheckCategory[] | undefined,
  };

  const result = await scanner.scan(options);

  if (options.json) {
    renderJson(result);
  } else {
    renderTerminal(result, options.verbose);
  }

  if (options.failBelow !== undefined && result.score < options.failBelow) {
    process.exit(2);
  }
}
