import type {
  AgentScanner,
  DetectionResult,
  Finding,
  FixResult,
  ScanOptions,
  ScanResult,
} from "../../core/types.js";
import { detectOpenClaw } from "./detector.js";
import { runCliAudit, runCliSecrets, runCliSandbox } from "./cli-runner.js";
import { readConfig, runConfigChecks } from "./config-reader.js";
import { normalizeFindings } from "./normalizer.js";
import { computeScore } from "../../core/scorer.js";

export class OpenClawScanner implements AgentScanner {
  readonly id = "openclaw";
  readonly label = "OpenClaw";

  private detection: DetectionResult | null = null;

  async detect(): Promise<DetectionResult> {
    this.detection = await detectOpenClaw();
    return this.detection;
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    if (!this.detection) {
      this.detection = await detectOpenClaw();
    }

    if (!this.detection.detected) {
      throw new Error(
        this.detection.error ?? "OpenClaw not detected"
      );
    }

    const warnings: string[] = [];
    const cliFindings: Array<{
      checkId: string;
      severity: string;
      title: string;
      detail: string;
      remediation?: string;
    }> = [];
    let cliChecksRun = 0;
    const timeout = options.timeout ?? 30_000;

    // Layer 1: Exec CLI commands (primary)
    if (this.detection.binaryPath) {
      try {
        const auditResult = await runCliAudit(
          this.detection.binaryPath,
          options.deep ?? false,
          timeout
        );
        cliFindings.push(...auditResult.findings);
        // Checks run = findings + passing checks (estimate from summary)
        cliChecksRun = auditResult.checksRun;
      } catch (err) {
        warnings.push(
          `openclaw security audit failed: ${err instanceof Error ? err.message : String(err)}. Running config-only scan.`
        );
      }

      try {
        const secretsResult = await runCliSecrets(
          this.detection.binaryPath,
          timeout
        );
        cliFindings.push(...secretsResult.findings);
        cliChecksRun += secretsResult.findings.length > 0 ? secretsResult.findings.length : 1;
      } catch (err) {
        if (cliChecksRun > 0) {
          warnings.push(
            `openclaw secrets audit failed: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }

      try {
        const sandboxResult = await runCliSandbox(
          this.detection.binaryPath,
          timeout
        );
        cliFindings.push(...sandboxResult.findings);
        cliChecksRun += sandboxResult.findings.length > 0 ? sandboxResult.findings.length : 1;
      } catch (err) {
        if (cliChecksRun > 0) {
          warnings.push(
            `openclaw sandbox explain failed: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }
    } else {
      warnings.push(
        "OpenClaw binary not found in PATH. Running config-only scan."
      );
    }

    // Normalize CLI findings with correct provenance
    const enrichedCliFindings = normalizeFindings(cliFindings, "cli", warnings);

    // Layer 2: Config fallback (supplement or primary if CLI unavailable)
    let configFindings: Finding[] = [];
    let configChecksRun = 0;
    if (this.detection.configPath) {
      try {
        const config = await readConfig(this.detection.configPath);
        const configResult = runConfigChecks(config);
        configChecksRun = configResult.checksRun;

        // Normalize config findings with correct provenance
        const enrichedConfigFindings = normalizeFindings(
          configResult.findings,
          "config",
          warnings
        );

        // Only add config findings that don't duplicate CLI findings
        const cliCheckIds = new Set(enrichedCliFindings.map((f) => f.checkId));
        configFindings = enrichedConfigFindings.filter(
          (f) => !cliCheckIds.has(f.checkId)
        );
      } catch (err) {
        warnings.push(
          `Config parsing failed: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Merge findings
    const allFindings = [...enrichedCliFindings, ...configFindings];

    // Filter by category if requested
    const filteredFindings = options.categories
      ? allFindings.filter((f) => options.categories!.includes(f.category))
      : allFindings;

    // Total checks run (CLI + non-duplicate config checks)
    const checksRun = cliChecksRun > 0
      ? cliChecksRun + Math.max(0, configChecksRun - enrichedCliFindings.length)
      : configChecksRun;

    // Score
    const scoreResult = computeScore(filteredFindings, checksRun);

    return {
      agent: this.id,
      version: this.detection.version ?? "unknown",
      timestamp: Date.now(),
      ...scoreResult,
      findings: filteredFindings,
      warnings,
    };
  }

  async fix(findings: Finding[], dryRun: boolean): Promise<FixResult[]> {
    if (!this.detection?.binaryPath) {
      return [
        {
          checkId: "*",
          applied: false,
          description: "Cannot run fixes without OpenClaw CLI",
          error: "OpenClaw binary not found",
        },
      ];
    }

    const { runCliFix } = await import("./cli-runner.js");
    return runCliFix(this.detection.binaryPath, dryRun);
  }
}
