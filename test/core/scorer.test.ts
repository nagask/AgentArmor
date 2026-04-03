import { describe, it, expect } from "vitest";
import { computeScore } from "../../src/core/scorer.js";
import type { Finding } from "../../src/core/types.js";

function makeFinding(
  overrides: Partial<Finding> & { checkId: string; severity: Finding["severity"] }
): Finding {
  return {
    category: "gateway-exposure",
    title: "Test finding",
    detail: "Test detail",
    blastRadius: "Test blast radius",
    source: "cli",
    ...overrides,
  };
}

describe("computeScore", () => {
  it("returns 100 with zero findings", () => {
    const result = computeScore([], 41);
    expect(result.score).toBe(100);
    expect(result.grade).toBe("A");
    expect(result.gradeCapped).toBe(false);
    expect(result.blockers).toBe(0);
  });

  it("deducts correctly for a single critical finding", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "gateway.bind_no_auth",
        severity: "critical",
        category: "gateway-exposure",
      }),
    ];
    const result = computeScore(findings, 41);
    // critical deduction: 25 * 0.4 = 10 → score 90
    expect(result.score).toBe(90);
  });

  it("caps grade to D for critical in gateway-exposure", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "gateway.bind_no_auth",
        severity: "critical",
        category: "gateway-exposure",
      }),
    ];
    const result = computeScore(findings, 41);
    expect(result.grade).toBe("D");
    expect(result.gradeCapped).toBe(true);
    expect(result.gradeCappedReason).toContain("gateway-exposure");
  });

  it("caps grade to D for critical in sandbox-isolation", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "sandbox.missing",
        severity: "critical",
        category: "sandbox-isolation",
      }),
    ];
    const result = computeScore(findings, 41);
    expect(result.grade).toBe("D");
    expect(result.gradeCapped).toBe(true);
  });

  it("caps grade to C for critical in non-high-severity category", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "hooks.path_root",
        severity: "critical",
        category: "hooks-webhooks",
      }),
    ];
    const result = computeScore(findings, 41);
    // hooks critical deduction: 3 * 0.4 = 1.2 → score 99
    // But grade capped at C because of critical
    expect(result.grade).toBe("C");
    expect(result.gradeCapped).toBe(true);
  });

  it("caps grade to F for 3+ criticals", () => {
    const findings: Finding[] = [
      makeFinding({ checkId: "c1", severity: "critical", category: "hooks-webhooks" }),
      makeFinding({ checkId: "c2", severity: "critical", category: "secrets" }),
      makeFinding({ checkId: "c3", severity: "critical", category: "browser-control" }),
    ];
    const result = computeScore(findings, 41);
    expect(result.grade).toBe("F");
    expect(result.gradeCapped).toBe(true);
    expect(result.blockers).toBe(3);
  });

  it("does not cap grade when no criticals", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "gateway.token_too_short",
        severity: "warn",
        category: "gateway-exposure",
      }),
    ];
    const result = computeScore(findings, 41);
    expect(result.gradeCapped).toBe(false);
  });

  it("deducts correctly for a single warn finding", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "gateway.token_too_short",
        severity: "warn",
        category: "gateway-exposure",
      }),
    ];
    const result = computeScore(findings, 41);
    // warn deduction: 25 * 0.15 = 3.75, rounded
    expect(result.score).toBe(96);
  });

  it("caps deductions at category weight", () => {
    const findings: Finding[] = [
      makeFinding({ checkId: "gw1", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "gw2", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "gw3", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "gw4", severity: "critical", category: "gateway-exposure" }),
    ];
    const result = computeScore(findings, 41);
    expect(result.score).toBe(75);
  });

  it("caps info deductions at 20% of category weight", () => {
    const findings: Finding[] = Array.from({ length: 20 }, (_, i) =>
      makeFinding({ checkId: `info${i}`, severity: "info", category: "gateway-exposure" })
    );
    const result = computeScore(findings, 41);
    expect(result.score).toBe(95);
  });

  it("computes coverage based on checksRun", () => {
    const result = computeScore([], 41);
    expect(result.coverage).toBe(100);

    const partialResult = computeScore([], 18);
    expect(partialResult.coverage).toBe(44); // 18/41 ≈ 44%

    const configOnly = computeScore([], 7);
    expect(configOnly.coverage).toBe(17); // 7/41 ≈ 17%
  });

  it("scores multiple categories independently", () => {
    const findings: Finding[] = [
      makeFinding({ checkId: "gw1", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "sec1", severity: "warn", category: "secrets" }),
      makeFinding({ checkId: "perm1", severity: "warn", category: "permissions" }),
    ];
    const result = computeScore(findings, 41);

    const gw = result.categories.find((c) => c.category === "gateway-exposure")!;
    expect(gw.deducted).toBe(10); // 25 * 0.4

    const sec = result.categories.find((c) => c.category === "secrets")!;
    expect(sec.deducted).toBeCloseTo(2.3, 0); // 15 * 0.15 = 2.25, rounded to 2.3

    const perm = result.categories.find((c) => c.category === "permissions")!;
    expect(perm.deducted).toBeCloseTo(1.5, 0); // 10 * 0.15 = 1.5
  });
});
