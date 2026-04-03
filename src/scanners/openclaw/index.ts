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
    const allRawFindings: Array<{
      checkId: string;
      severity: string;
      title: string;
      detail: string;
      remediation?: string;
    }> = [];
    let cliAvailable = false;
    const timeout = options.timeout ?? 30_000;

    // Layer 1: Exec CLI commands (primary)
    if (this.detection.binaryPath) {
      try {
        const auditResult = await runCliAudit(
          this.detection.binaryPath,
          options.deep ?? false,
          timeout
        );
        allRawFindings.push(...auditResult.findings);
        cliAvailable = true;
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
        allRawFindings.push(...secretsResult.findings);
      } catch (err) {
        if (cliAvailable) {
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
        allRawFindings.push(...sandboxResult.findings);
      } catch (err) {
        if (cliAvailable) {
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

    // Layer 2: Config fallback (supplement or primary if CLI unavailable)
    if (this.detection.configPath) {
      try {
        const config = await readConfig(this.detection.configPath);
        const configFindings = runConfigChecks(config);
        // Only add config findings that don't duplicate CLI findings
        const cliCheckIds = new Set(allRawFindings.map((f) => f.checkId));
        for (const cf of configFindings) {
          if (!cliCheckIds.has(cf.checkId)) {
            allRawFindings.push(cf);
          }
        }
      } catch (err) {
        warnings.push(
          `Config parsing failed: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Normalize + enrich
    const findings = normalizeFindings(allRawFindings, warnings);

    // Filter by category if requested
    const filteredFindings = options.categories
      ? findings.filter((f) => options.categories!.includes(f.category))
      : findings;

    // Score
    const { score, coverage, grade, categories } = computeScore(
      filteredFindings,
      cliAvailable
    );

    return {
      agent: this.id,
      version: this.detection.version ?? "unknown",
      timestamp: Date.now(),
      score,
      coverage,
      grade,
      categories,
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
