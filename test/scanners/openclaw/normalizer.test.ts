import { describe, it, expect } from "vitest";
import { normalizeFindings } from "../../../src/scanners/openclaw/normalizer.js";

describe("normalizeFindings", () => {
  it("normalizes raw findings into enriched findings", () => {
    const warnings: string[] = [];
    const findings = normalizeFindings(
      [
        {
          checkId: "gateway.bind_no_auth",
          severity: "critical",
          title: "Gateway binds beyond loopback",
          detail: "No auth configured",
          remediation: "Fix it",
        },
      ],
      warnings
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe("gateway-exposure");
    expect(findings[0].blastRadius).toContain("local network");
    expect(findings[0].atlasId).toBe("T-ACCESS-001");
    expect(findings[0].source).toBe("cli");
    expect(warnings).toHaveLength(0);
  });

  it("deduplicates by checkId (first wins)", () => {
    const warnings: string[] = [];
    const findings = normalizeFindings(
      [
        {
          checkId: "gateway.bind_no_auth",
          severity: "critical",
          title: "First occurrence",
          detail: "CLI version",
        },
        {
          checkId: "gateway.bind_no_auth",
          severity: "critical",
          title: "Second occurrence",
          detail: "Config version",
        },
      ],
      warnings
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe("First occurrence");
  });

  it("handles unknown severity with warning", () => {
    const warnings: string[] = [];
    const findings = normalizeFindings(
      [
        {
          checkId: "test.unknown",
          severity: "danger" as string,
          title: "Unknown severity",
          detail: "Test",
        },
      ],
      warnings
    );

    expect(findings[0].severity).toBe("info");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("Unknown severity");
  });

  it("handles empty input", () => {
    const warnings: string[] = [];
    const findings = normalizeFindings([], warnings);
    expect(findings).toHaveLength(0);
    expect(warnings).toHaveLength(0);
  });
});
