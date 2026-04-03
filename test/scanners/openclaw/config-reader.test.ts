import { describe, it, expect } from "vitest";
import { runConfigChecks, type OpenClawConfig } from "../../../src/scanners/openclaw/config-reader.js";

describe("runConfigChecks", () => {
  it("detects gateway bind without auth", () => {
    const config: OpenClawConfig = {
      gateway: { bind: "lan" },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.bind_no_auth")).toBe(true);
  });

  it("does not flag loopback bind", () => {
    const config: OpenClawConfig = {
      gateway: { bind: "loopback" },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.bind_no_auth")).toBe(false);
  });

  it("does not flag bind with auth configured", () => {
    const config: OpenClawConfig = {
      gateway: {
        bind: "lan",
        auth: { mode: "token", token: "a-secure-token-here-1234" },
      },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.bind_no_auth")).toBe(false);
  });

  it("detects plaintext gateway password", () => {
    const config: OpenClawConfig = {
      gateway: { auth: { password: "mypassword123" } },
    };
    const { findings } = runConfigChecks(config);
    expect(
      findings.some((f) => f.checkId === "config.secrets.gateway_password_in_config")
    ).toBe(true);
  });

  it("does not flag env var password references", () => {
    const config: OpenClawConfig = {
      gateway: { auth: { password: "${GATEWAY_PASSWORD}" } },
    };
    const { findings } = runConfigChecks(config);
    expect(
      findings.some((f) => f.checkId === "config.secrets.gateway_password_in_config")
    ).toBe(false);
  });

  it("detects hooks path root", () => {
    const config: OpenClawConfig = {
      hooks: { path: "/" },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "hooks.path_root")).toBe(true);
  });

  it("detects logging redaction off", () => {
    const config: OpenClawConfig = {
      logging: { redactSensitive: "off" },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "logging.redact_off")).toBe(true);
  });

  it("detects tailscale funnel", () => {
    const config: OpenClawConfig = {
      gateway: { tailscale: { mode: "funnel" } },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.tailscale_funnel")).toBe(true);
  });

  it("detects insecure control UI auth", () => {
    const config: OpenClawConfig = {
      gateway: { controlUi: { allowInsecureAuth: true } },
    };
    const { findings } = runConfigChecks(config);
    expect(
      findings.some((f) => f.checkId === "gateway.control_ui.insecure_auth")
    ).toBe(true);
  });

  it("returns empty findings for a clean config", () => {
    const config: OpenClawConfig = {
      gateway: {
        bind: "loopback",
        auth: { mode: "token", token: "${GATEWAY_TOKEN}" },
      },
      hooks: { path: "/hooks", token: "${HOOKS_TOKEN}" },
      logging: { redactSensitive: "tools" },
    };
    const { findings } = runConfigChecks(config);
    expect(findings).toHaveLength(0);
  });

  it("returns checksRun count", () => {
    const config: OpenClawConfig = {};
    const { checksRun } = runConfigChecks(config);
    expect(checksRun).toBeGreaterThan(0);
  });

  // ── New checks ──────────────────────────────────────────────

  it("detects short gateway token", () => {
    const config: OpenClawConfig = {
      gateway: { auth: { token: "short" } },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "gateway.token_too_short")).toBe(true);
  });

  it("detects short hooks token", () => {
    const config: OpenClawConfig = {
      hooks: { token: "abc" },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "hooks.token_too_short")).toBe(true);
  });

  it("detects hooks token reusing gateway token", () => {
    const config: OpenClawConfig = {
      gateway: { auth: { token: "same-token-1234567890abcdef" } },
      hooks: { token: "same-token-1234567890abcdef" },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "hooks.token_reuse_gateway_token")).toBe(true);
  });

  it("detects unset hooks default session key", () => {
    const config: OpenClawConfig = {
      hooks: { enabled: true },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "hooks.default_session_key_unset")).toBe(true);
  });

  it("detects session key override without prefixes (remote)", () => {
    const config: OpenClawConfig = {
      gateway: { bind: "lan" },
      hooks: { allowRequestSessionKey: true },
    };
    const { findings } = runConfigChecks(config);
    const f = findings.find((f) => f.checkId === "hooks.request_session_key_prefixes_missing");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("critical");
  });

  it("detects session key override without prefixes (loopback = warn)", () => {
    const config: OpenClawConfig = {
      gateway: { bind: "loopback" },
      hooks: { allowRequestSessionKey: true },
    };
    const { findings } = runConfigChecks(config);
    const f = findings.find((f) => f.checkId === "hooks.request_session_key_prefixes_missing");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("warn");
  });

  it("detects browser control without auth", () => {
    const config: OpenClawConfig = {
      browser: { enabled: true },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "browser.control_no_auth")).toBe(true);
  });

  it("detects open DM policy on channels", () => {
    const config: OpenClawConfig = {
      channels: {
        discord: { dm: { policy: "open" } },
      },
    };
    const { findings } = runConfigChecks(config);
    expect(findings.some((f) => f.checkId === "channels.discord.dm.open")).toBe(true);
  });

  it("detects open group policy with elevated tools", () => {
    const config: OpenClawConfig = {
      tools: { elevated: { enabled: true } },
      channels: {
        slack: { groupPolicy: "open" },
      },
    };
    const { findings } = runConfigChecks(config);
    expect(
      findings.some((f) => f.checkId === "security.exposure.open_groups_with_elevated")
    ).toBe(true);
  });

  it("detects control UI device auth disabled", () => {
    const config: OpenClawConfig = {
      gateway: { controlUi: { dangerouslyDisableDeviceAuth: true } },
    };
    const { findings } = runConfigChecks(config);
    expect(
      findings.some((f) => f.checkId === "gateway.control_ui.device_auth_disabled")
    ).toBe(true);
  });
});
