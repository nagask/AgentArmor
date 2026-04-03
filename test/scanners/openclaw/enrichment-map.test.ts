import { describe, it, expect } from "vitest";
import { getEnrichment } from "../../../src/scanners/openclaw/enrichment-map.js";

describe("getEnrichment", () => {
  it("returns exact match for known checkIds", () => {
    const e = getEnrichment("gateway.bind_no_auth");
    expect(e.category).toBe("gateway-exposure");
    expect(e.blastRadius).toContain("local network");
    expect(e.atlasId).toBe("T-ACCESS-001");
  });

  it("returns prefix match for dynamic checkIds", () => {
    const e = getEnrichment("tools.elevated.allowFrom.discord.wildcard");
    expect(e.category).toBe("elevated-exec");
    expect(e.atlasId).toBe("T-IMPACT-001");
  });

  it("returns channel prefix match for unknown channel providers", () => {
    const e = getEnrichment("channels.matrix.dm.open");
    expect(e.category).toBe("channel-access");
  });

  it("returns default enrichment for completely unknown checkIds", () => {
    const e = getEnrichment("totally.unknown.check");
    expect(e.category).toBe("runtime-config");
    expect(e.blastRadius).toContain("doesn't have detailed context");
  });

  it("has blast radius for every known check", () => {
    const knownChecks = [
      "gateway.bind_no_auth",
      "gateway.loopback_no_auth",
      "gateway.tailscale_funnel",
      "browser.control_no_auth",
      "channels.discord.dm.open",
      "hooks.path_root",
      "fs.state_dir.perms_world_writable",
      "config.secrets.gateway_password_in_config",
      "plugins.code_safety",
      "skills.code_safety",
    ];

    for (const checkId of knownChecks) {
      const e = getEnrichment(checkId);
      expect(e.blastRadius.length).toBeGreaterThan(10);
      expect(e.category).not.toBe("runtime-config");
    }
  });
});
