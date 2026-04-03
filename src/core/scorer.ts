import type { Finding, CategoryScore, CheckCategory } from "./types.js";
import { CATEGORY_WEIGHTS, CATEGORY_LABELS } from "./types.js";
import { KNOWN_CHECK_COUNT } from "../scanners/openclaw/enrichment-map.js";

interface ScoreResult {
  score: number;
  coverage: number;
  grade: string;
  categories: CategoryScore[];
}

const SEVERITY_MULTIPLIERS = {
  critical: 0.4,
  warn: 0.15,
  info: 0.02,
} as const;

function computeGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function computeScore(
  findings: Finding[],
  cliAvailable: boolean
): ScoreResult {
  // Group findings by category
  const grouped = new Map<CheckCategory, Finding[]>();
  for (const f of findings) {
    const arr = grouped.get(f.category) ?? [];
    arr.push(f);
    grouped.set(f.category, arr);
  }

  // Compute per-category scores
  const categories: CategoryScore[] = [];
  let totalDeducted = 0;

  for (const [category, weight] of Object.entries(CATEGORY_WEIGHTS) as Array<
    [CheckCategory, number]
  >) {
    const categoryFindings = grouped.get(category) ?? [];
    const counts = { critical: 0, warn: 0, info: 0 };
    let deducted = 0;

    for (const f of categoryFindings) {
      counts[f.severity]++;
      const multiplier = SEVERITY_MULTIPLIERS[f.severity];
      deducted += weight * multiplier;
    }

    // Info deductions capped at 20% of category weight
    const infoDeduction = counts.info * weight * SEVERITY_MULTIPLIERS.info;
    const infoCap = weight * 0.2;
    const cappedInfoDeduction = Math.min(infoDeduction, infoCap);

    // Recalculate: critical + warn (uncapped within category) + capped info
    const critWarnDeduction =
      counts.critical * weight * SEVERITY_MULTIPLIERS.critical +
      counts.warn * weight * SEVERITY_MULTIPLIERS.warn;

    deducted = Math.min(critWarnDeduction + cappedInfoDeduction, weight);
    totalDeducted += deducted;

    categories.push({
      category,
      label: CATEGORY_LABELS[category],
      weight,
      score: Math.max(0, Math.round((weight - deducted) * 10) / 10),
      maxPoints: weight,
      deducted: Math.round(deducted * 10) / 10,
      findings: counts,
    });
  }

  const score = Math.max(0, Math.round(100 - totalDeducted));

  // Coverage: estimate based on whether CLI was available
  // CLI provides ~100% of checks; config-only provides ~30%
  const uniqueCheckIds = new Set(findings.map((f) => f.checkId)).size;
  const coverage = cliAvailable
    ? 100
    : Math.min(100, Math.round((uniqueCheckIds / KNOWN_CHECK_COUNT) * 100));

  return {
    score,
    coverage,
    grade: computeGrade(score),
    categories,
  };
}
