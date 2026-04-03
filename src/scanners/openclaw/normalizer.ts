import type { Finding } from "../../core/types.js";
import { getEnrichment } from "./enrichment-map.js";

export interface RawFinding {
  checkId: string;
  severity: string;
  title: string;
  detail: string;
  remediation?: string;
}

export function normalizeFindings(
  rawFindings: RawFinding[],
  warnings: string[]
): Finding[] {
  const seen = new Set<string>();
  const findings: Finding[] = [];

  for (const raw of rawFindings) {
    // Dedup by checkId — first occurrence wins (CLI over config)
    if (seen.has(raw.checkId)) continue;
    seen.add(raw.checkId);

    const severity = raw.severity as "critical" | "warn" | "info";
    if (!["critical", "warn", "info"].includes(severity)) {
      warnings.push(
        `Unknown severity "${raw.severity}" for checkId "${raw.checkId}", treating as info`
      );
    }

    const enrichment = getEnrichment(raw.checkId);

    findings.push({
      checkId: raw.checkId,
      category: enrichment.category,
      severity: ["critical", "warn", "info"].includes(severity)
        ? severity
        : "info",
      title: raw.title,
      detail: raw.detail,
      remediation: raw.remediation,
      blastRadius: enrichment.blastRadius,
      atlasId: enrichment.atlasId,
      source: "cli",
    });
  }

  return findings;
}
