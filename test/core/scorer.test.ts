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
    const result = computeScore([], true);
    expect(result.score).toBe(100);
    expect(result.grade).toBe("A");
    expect(result.coverage).toBe(100);
  });

  it("deducts correctly for a single critical finding", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "gateway.bind_no_auth",
        severity: "critical",
        category: "gateway-exposure",
      }),
    ];
    const result = computeScore(findings, true);
    // critical deduction: 25 * 0.4 = 10
    expect(result.score).toBe(90);
    expect(result.grade).toBe("A");
  });

  it("deducts correctly for a single warn finding", () => {
    const findings: Finding[] = [
      makeFinding({
        checkId: "gateway.token_too_short",
        severity: "warn",
        category: "gateway-exposure",
      }),
    ];
    const result = computeScore(findings, true);
    // warn deduction: 25 * 0.15 = 3.75, rounded
    expect(result.score).toBe(96);
  });

  it("caps deductions at category weight", () => {
    // 4 critical findings in gateway (25% weight)
    // 4 * 25 * 0.4 = 40, but capped at 25
    const findings: Finding[] = [
      makeFinding({ checkId: "gw1", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "gw2", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "gw3", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "gw4", severity: "critical", category: "gateway-exposure" }),
    ];
    const result = computeScore(findings, true);
    expect(result.score).toBe(75);
  });

  it("caps info deductions at 20% of category weight", () => {
    // 20 info findings in gateway (25% weight)
    // 20 * 25 * 0.02 = 10, but info cap is 25 * 0.2 = 5
    const findings: Finding[] = Array.from({ length: 20 }, (_, i) =>
      makeFinding({ checkId: `info${i}`, severity: "info", category: "gateway-exposure" })
    );
    const result = computeScore(findings, true);
    expect(result.score).toBe(95);
  });

  it("assigns correct grades", () => {
    expect(computeScore([], true).grade).toBe("A");

    // Score 75 = B (3 criticals in gateway = capped at 25)
    const criticals = [
      makeFinding({ checkId: "c1", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "c2", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "c3", severity: "critical", category: "gateway-exposure" }),
    ];
    expect(computeScore(criticals, true).grade).toBe("B");
  });

  it("computes coverage based on CLI availability", () => {
    const result = computeScore([], true);
    expect(result.coverage).toBe(100);

    const resultNoCliNoFindings = computeScore([], false);
    expect(resultNoCliNoFindings.coverage).toBe(0);
  });

  it("scores multiple categories independently", () => {
    const findings: Finding[] = [
      makeFinding({ checkId: "gw1", severity: "critical", category: "gateway-exposure" }),
      makeFinding({ checkId: "sec1", severity: "warn", category: "secrets" }),
      makeFinding({ checkId: "perm1", severity: "warn", category: "permissions" }),
    ];
    const result = computeScore(findings, true);

    const gw = result.categories.find((c) => c.category === "gateway-exposure")!;
    expect(gw.deducted).toBe(10); // 25 * 0.4

    const sec = result.categories.find((c) => c.category === "secrets")!;
    expect(sec.deducted).toBeCloseTo(2.3, 0); // 15 * 0.15 = 2.25, rounded to 2.3

    const perm = result.categories.find((c) => c.category === "permissions")!;
    expect(perm.deducted).toBeCloseTo(1.5, 0); // 10 * 0.15 = 1.5
  });
});
