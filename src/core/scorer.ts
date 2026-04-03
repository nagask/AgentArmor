import type { Finding, CategoryScore, CheckCategory } from "./types.js";
import { CATEGORY_WEIGHTS, CATEGORY_LABELS } from "./types.js";

const TOTAL_KNOWN_CHECKS = 41;

interface ScoreResult {
  score: number;
  coverage: number;
  grade: string;
  gradeCapped: boolean;
  gradeCappedReason?: string;
  blockers: number;
  categories: CategoryScore[];
}

const SEVERITY_MULTIPLIERS = {
  critical: 0.4,
  warn: 0.15,
  info: 0.02,
} as const;

const HIGH_SEVERITY_CATEGORIES: CheckCategory[] = [
  "gateway-exposure",
  "sandbox-isolation",
];

function computeGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function capGrade(
  grade: string,
  maxGrade: string
): string {
  const order = ["F", "D", "C", "B", "A"];
  const gradeIdx = order.indexOf(grade);
  const capIdx = order.indexOf(maxGrade);
  if (gradeIdx > capIdx) return maxGrade;
  return grade;
}

export function computeScore(
  findings: Finding[],
  checksRun: number
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

    for (const f of categoryFindings) {
      counts[f.severity]++;
    }

    // Info deductions capped at 20% of category weight
    const infoDeduction = counts.info * weight * SEVERITY_MULTIPLIERS.info;
    const infoCap = weight * 0.2;
    const cappedInfoDeduction = Math.min(infoDeduction, infoCap);

    const critWarnDeduction =
      counts.critical * weight * SEVERITY_MULTIPLIERS.critical +
      counts.warn * weight * SEVERITY_MULTIPLIERS.warn;

    const deducted = Math.min(critWarnDeduction + cappedInfoDeduction, weight);
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

  // Grade caps based on critical findings
  const criticals = findings.filter((f) => f.severity === "critical");
  const blockers = criticals.length;
  let grade = computeGrade(score);
  let gradeCapped = false;
  let gradeCappedReason: string | undefined;

  if (blockers >= 3) {
    const capped = capGrade(grade, "F");
    if (capped !== grade) {
      gradeCapped = true;
      gradeCappedReason = `${blockers} critical findings`;
      grade = capped;
    }
  } else if (
    criticals.some((f) => HIGH_SEVERITY_CATEGORIES.includes(f.category))
  ) {
    const capped = capGrade(grade, "D");
    if (capped !== grade) {
      gradeCapped = true;
      gradeCappedReason = `critical finding in ${criticals.find((f) => HIGH_SEVERITY_CATEGORIES.includes(f.category))!.category}`;
      grade = capped;
    }
  } else if (blockers > 0) {
    const capped = capGrade(grade, "C");
    if (capped !== grade) {
      gradeCapped = true;
      gradeCappedReason = `${blockers} critical finding${blockers > 1 ? "s" : ""}`;
      grade = capped;
    }
  }

  // Coverage based on checks actually run
  const coverage = Math.min(
    100,
    Math.round((checksRun / TOTAL_KNOWN_CHECKS) * 100)
  );

  return {
    score,
    coverage,
    grade,
    gradeCapped,
    gradeCappedReason,
    blockers,
    categories,
  };
}
