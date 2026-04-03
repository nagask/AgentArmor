import { describe, it, expect } from "vitest";
import { runConfigChecks, type OpenClawConfig } from "../../../src/scanners/openclaw/config-reader.js";

describe("runConfigChecks", () => {
  it("detects gateway bind without auth", () => {
    const config: OpenClawConfig = {
      gateway: { bind: "lan" },
    };
    const findings = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.bind_no_auth")).toBe(
      true
    );
  });

  it("does not flag loopback bind", () => {
    const config: OpenClawConfig = {
      gateway: { bind: "loopback" },
    };
    const findings = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.bind_no_auth")).toBe(
      false
    );
  });

  it("does not flag bind with auth configured", () => {
    const config: OpenClawConfig = {
      gateway: {
        bind: "lan",
        auth: { mode: "token", token: "a-secure-token-here-1234" },
      },
    };
    const findings = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.bind_no_auth")).toBe(
      false
    );
  });

  it("detects plaintext gateway password", () => {
    const config: OpenClawConfig = {
      gateway: { auth: { password: "mypassword123" } },
    };
    const findings = runConfigChecks(config);
    expect(
      findings.some(
        (f) => f.checkId === "config.secrets.gateway_password_in_config"
      )
    ).toBe(true);
  });

  it("does not flag env var password references", () => {
    const config: OpenClawConfig = {
      gateway: { auth: { password: "${GATEWAY_PASSWORD}" } },
    };
    const findings = runConfigChecks(config);
    expect(
      findings.some(
        (f) => f.checkId === "config.secrets.gateway_password_in_config"
      )
    ).toBe(false);
  });

  it("detects hooks path root", () => {
    const config: OpenClawConfig = {
      hooks: { path: "/" },
    };
    const findings = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "hooks.path_root")).toBe(true);
  });

  it("detects logging redaction off", () => {
    const config: OpenClawConfig = {
      logging: { redactSensitive: "off" },
    };
    const findings = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "logging.redact_off")).toBe(
      true
    );
  });

  it("detects tailscale funnel", () => {
    const config: OpenClawConfig = {
      gateway: { tailscale: { mode: "funnel" } },
    };
    const findings = runConfigChecks(config);
    expect(
      findings.some((f) => f.checkId === "gateway.tailscale_funnel")
    ).toBe(true);
  });

  it("detects insecure control UI auth", () => {
    const config: OpenClawConfig = {
      gateway: { controlUi: { allowInsecureAuth: true } },
    };
    const findings = runConfigChecks(config);
    expect(
      findings.some(
        (f) => f.checkId === "gateway.control_ui.insecure_auth"
      )
    ).toBe(true);
  });

  it("returns empty for a clean config", () => {
    const config: OpenClawConfig = {
      gateway: {
        bind: "loopback",
        auth: { mode: "token", token: "${GATEWAY_TOKEN}" },
      },
      hooks: { path: "/hooks", token: "${HOOKS_TOKEN}" },
      logging: { redactSensitive: "tools" },
    };
    const findings = runConfigChecks(config);
    expect(findings).toHaveLength(0);
  });
});
