import { execFile } from "node:child_process";
import { z } from "zod";
import type { FixResult } from "../../core/types.js";

function execPromise(
  cmd: string,
  args: string[],
  timeout: number
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      cmd,
      args,
      { timeout, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve({ stdout, stderr });
        }
      }
    );
  });
}

// Zod schemas for validating CLI JSON output

const FindingSchema = z.object({
  checkId: z.string(),
  severity: z.enum(["info", "warn", "critical"]),
  title: z.string(),
  detail: z.string(),
  remediation: z.string().optional(),
});

const AuditReportSchema = z.object({
  ts: z.number(),
  summary: z.object({
    critical: z.number(),
    warn: z.number(),
    info: z.number(),
  }),
  findings: z.array(FindingSchema),
  deep: z
    .object({
      gateway: z
        .object({
          attempted: z.boolean(),
          url: z.string().nullable(),
          ok: z.boolean(),
          error: z.string().nullable(),
        })
        .optional(),
    })
    .optional(),
});

const SecretsReportSchema = z.object({
  ts: z.number().optional(),
  findings: z.array(FindingSchema),
});

const SandboxExplainSchema = z.object({
  findings: z.array(FindingSchema).optional(),
}).passthrough();

export type RawFinding = z.infer<typeof FindingSchema>;

export interface CliAuditResult {
  findings: RawFinding[];
  deep?: { gateway?: { attempted: boolean; ok: boolean } };
}

export interface CliSecretsResult {
  findings: RawFinding[];
}

export interface CliSandboxResult {
  findings: RawFinding[];
}

export async function runCliAudit(
  binaryPath: string,
  deep: boolean,
  timeout: number
): Promise<CliAuditResult> {
  const args = ["security", "audit", "--json"];
  if (deep) args.push("--deep");

  const { stdout } = await execPromise(binaryPath, args, timeout);
  const parsed = JSON.parse(stdout);
  const validated = AuditReportSchema.parse(parsed);

  return {
    findings: validated.findings,
    deep: validated.deep
      ? {
          gateway: validated.deep.gateway
            ? {
                attempted: validated.deep.gateway.attempted,
                ok: validated.deep.gateway.ok,
              }
            : undefined,
        }
      : undefined,
  };
}

export async function runCliSecrets(
  binaryPath: string,
  timeout: number
): Promise<CliSecretsResult> {
  const args = ["secrets", "audit", "--json"];

  const { stdout } = await execPromise(binaryPath, args, timeout);
  const parsed = JSON.parse(stdout);
  const validated = SecretsReportSchema.parse(parsed);

  return { findings: validated.findings };
}

export async function runCliSandbox(
  binaryPath: string,
  timeout: number
): Promise<CliSandboxResult> {
  const args = ["sandbox", "explain", "--json"];

  try {
    const { stdout } = await execPromise(binaryPath, args, timeout);
    const parsed = JSON.parse(stdout);
    const validated = SandboxExplainSchema.parse(parsed);
    return { findings: validated.findings ?? [] };
  } catch {
    // sandbox explain may not emit findings in all versions
    return { findings: [] };
  }
}

export async function runCliFix(
  binaryPath: string,
  dryRun: boolean
): Promise<FixResult[]> {
  if (dryRun) {
    // Run audit to see what would be fixed, but don't apply
    const args = ["security", "audit", "--json"];
    const { stdout } = await execPromise(binaryPath, args, 30_000);
    const parsed = JSON.parse(stdout);
    const validated = AuditReportSchema.parse(parsed);

    return validated.findings
      .filter((f) => f.remediation)
      .map((f) => ({
        checkId: f.checkId,
        applied: false,
        description: `Would fix: ${f.title} — ${f.remediation}`,
      }));
  }

  // Apply fixes
  const args = ["security", "audit", "--fix", "--json"];
  try {
    const { stdout } = await execPromise(binaryPath, args, 30_000);
    const parsed = JSON.parse(stdout);

    // The --fix output wraps: { fix: { changes, actions, errors }, report }
    const changes: string[] = parsed?.fix?.changes ?? [];
    const errors: string[] = parsed?.fix?.errors ?? [];

    const results: FixResult[] = changes.map((change: string) => ({
      checkId: "*",
      applied: true,
      description: change,
    }));

    for (const error of errors) {
      results.push({
        checkId: "*",
        applied: false,
        description: "Fix error",
        error,
      });
    }

    if (results.length === 0) {
      results.push({
        checkId: "*",
        applied: false,
        description: "No auto-fixable issues found",
      });
    }

    return results;
  } catch (err) {
    return [
      {
        checkId: "*",
        applied: false,
        description: "Failed to run openclaw security audit --fix",
        error: err instanceof Error ? err.message : String(err),
      },
    ];
  }
}
