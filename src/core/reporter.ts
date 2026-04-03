import chalk from "chalk";
import type { ScanResult, Finding, CategoryScore } from "./types.js";

function severityColor(severity: string): (text: string) => string {
  switch (severity) {
    case "critical":
      return chalk.red;
    case "warn":
      return chalk.yellow;
    case "info":
      return chalk.blue;
    default:
      return chalk.white;
  }
}

function gradeColor(grade: string): (text: string) => string {
  switch (grade) {
    case "A":
      return chalk.green;
    case "B":
      return chalk.cyan;
    case "C":
      return chalk.yellow;
    case "D":
      return chalk.red;
    case "F":
      return chalk.bgRed.white;
    default:
      return chalk.white;
  }
}

function gradeLabel(grade: string): string {
  switch (grade) {
    case "A":
      return "Hardened";
    case "B":
      return "Good Baseline";
    case "C":
      return "Needs Attention";
    case "D":
      return "Significant Risk";
    case "F":
      return "Dangerous";
    default:
      return "";
  }
}

function padRight(str: string, len: number): string {
  return str.length >= len ? str : str + " ".repeat(len - str.length);
}

function renderCategoryLine(cat: CategoryScore): string {
  const label = padRight(cat.label, 20);
  const scoreStr = `${cat.score}/${cat.maxPoints}`;
  const counts: string[] = [];

  if (cat.findings.critical > 0)
    counts.push(chalk.red(`${cat.findings.critical} critical`));
  if (cat.findings.warn > 0)
    counts.push(chalk.yellow(`${cat.findings.warn} warn`));
  if (cat.findings.info > 0)
    counts.push(chalk.blue(`${cat.findings.info} info`));

  const countsStr = counts.length > 0 ? `  [${counts.join(", ")}]` : "";
  const dots = ".".repeat(
    Math.max(1, 40 - label.length - scoreStr.length)
  );

  return `  ${label} ${chalk.dim(dots)} ${scoreStr}${countsStr}`;
}

function renderFinding(finding: Finding): string {
  const color = severityColor(finding.severity);
  const lines: string[] = [];

  lines.push(color(`  ${finding.checkId}`));
  lines.push(`    ${finding.title}`);
  lines.push(chalk.dim(`    Blast radius: `) + finding.blastRadius);

  if (finding.remediation) {
    lines.push(chalk.green(`    Fix: `) + finding.remediation);
  }

  return lines.join("\n");
}

export function renderTerminal(
  result: ScanResult,
  verbose?: boolean
): void {
  const out = process.stdout;
  const color = gradeColor(result.grade);

  // Header
  out.write("\n");
  out.write(
    chalk.bold(`  AgentArmor v0.1.0`) +
      chalk.dim(` — ${result.agent} v${result.version}`) +
      "\n"
  );
  out.write("\n");

  // Score
  const coverageStr =
    result.coverage < 100
      ? chalk.dim(` (${result.coverage}% coverage)`)
      : "";
  out.write(
    `  Score: ${color(chalk.bold(`${result.score}/100`))} ${color(`(${result.grade} — ${gradeLabel(result.grade)})`)}${coverageStr}\n`
  );
  out.write("\n");

  // Category breakdown
  for (const cat of result.categories) {
    out.write(renderCategoryLine(cat) + "\n");
  }

  // Findings by severity
  const criticals = result.findings.filter(
    (f) => f.severity === "critical"
  );
  const warns = result.findings.filter((f) => f.severity === "warn");
  const infos = result.findings.filter((f) => f.severity === "info");

  if (criticals.length > 0) {
    out.write("\n");
    out.write(
      chalk.red.bold(`  CRITICAL (${criticals.length})`) + "\n"
    );
    out.write("\n");
    for (const f of criticals) {
      out.write(renderFinding(f) + "\n\n");
    }
  }

  if (warns.length > 0) {
    out.write(chalk.yellow.bold(`  WARN (${warns.length})`) + "\n");
    out.write("\n");
    for (const f of warns) {
      out.write(renderFinding(f) + "\n\n");
    }
  }

  if (verbose && infos.length > 0) {
    out.write(chalk.blue.bold(`  INFO (${infos.length})`) + "\n");
    out.write("\n");
    for (const f of infos) {
      out.write(renderFinding(f) + "\n\n");
    }
  } else if (infos.length > 0) {
    out.write(chalk.dim(`  + ${infos.length} info findings (use --verbose to show)\n`));
  }

  // Warnings from scan process
  if (result.warnings.length > 0 && verbose) {
    out.write("\n");
    out.write(chalk.dim("  Scan warnings:\n"));
    for (const w of result.warnings) {
      out.write(chalk.dim(`    - ${w}\n`));
    }
  }

  // Footer
  out.write("\n");
  out.write(
    chalk.dim(
      '  Run "agentarmor explain <checkId>" for detailed attack scenarios.'
    ) + "\n"
  );
  out.write(
    chalk.dim('  Run "agentarmor fix" to apply safe remediations.') + "\n"
  );
  out.write("\n");
}

export function renderJson(result: ScanResult): void {
  // Write JSON to stdout, warnings to stderr
  for (const w of result.warnings) {
    process.stderr.write(`warning: ${w}\n`);
  }
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}
