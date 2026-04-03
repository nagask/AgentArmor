import { readFile } from "node:fs/promises";
import JSON5 from "json5";
import type { RawFinding } from "./normalizer.js";

export interface OpenClawConfig {
  gateway?: {
    bind?: string;
    auth?: {
      mode?: string;
      token?: string;
      password?: string;
    };
    tailscale?: {
      mode?: string;
    };
    controlUi?: {
      enabled?: boolean;
      allowInsecureAuth?: boolean;
      dangerouslyDisableDeviceAuth?: boolean;
    };
  };
  hooks?: {
    enabled?: boolean;
    token?: string;
    path?: string;
    defaultSessionKey?: string;
    allowRequestSessionKey?: boolean;
  };
  browser?: {
    enabled?: boolean;
  };
  logging?: {
    redactSensitive?: string;
  };
  [key: string]: unknown;
}

export async function readConfig(configPath: string): Promise<OpenClawConfig> {
  const content = await readFile(configPath, "utf-8");
  if (!content.trim()) {
    throw new Error("Config file is empty");
  }
  return JSON5.parse(content) as OpenClawConfig;
}

/**
 * Run basic config-based checks when CLI is unavailable.
 * These are a SUBSET of what the full CLI audit provides.
 */
export function runConfigChecks(config: OpenClawConfig): RawFinding[] {
  const findings: RawFinding[] = [];

  // Gateway bind without auth
  if (
    config.gateway?.bind &&
    config.gateway.bind !== "loopback" &&
    !config.gateway.auth?.mode &&
    !config.gateway.auth?.token
  ) {
    findings.push({
      checkId: "gateway.bind_no_auth",
      severity: "critical",
      title: "Gateway binds beyond loopback without authentication",
      detail: `Gateway bind is set to "${config.gateway.bind}" but no authentication is configured.`,
      remediation:
        'Set gateway.auth.mode to "token" or change gateway.bind to "loopback"',
    });
  }

  // Gateway password in config
  if (config.gateway?.auth?.password) {
    const isEnvRef = config.gateway.auth.password.includes("${");
    if (!isEnvRef) {
      findings.push({
        checkId: "config.secrets.gateway_password_in_config",
        severity: "warn",
        title: "Gateway password stored in plaintext in config",
        detail:
          "The gateway password is stored directly in the config file instead of using an environment variable reference.",
        remediation:
          'Use ${ENV_VAR_NAME} syntax: "password": "${GATEWAY_PASSWORD}"',
      });
    }
  }

  // Hooks token in config
  if (config.hooks?.token) {
    const isEnvRef = config.hooks.token.includes("${");
    if (!isEnvRef) {
      findings.push({
        checkId: "config.secrets.hooks_token_in_config",
        severity: "info",
        title: "Hooks token stored in config file",
        detail:
          "The hooks token is stored in the config file. Consider using an environment variable reference.",
        remediation:
          'Use ${ENV_VAR_NAME} syntax: "token": "${HOOKS_TOKEN}"',
      });
    }
  }

  // Hooks path root
  if (config.hooks?.path === "/") {
    findings.push({
      checkId: "hooks.path_root",
      severity: "critical",
      title: "Hooks base path is set to '/'",
      detail:
        "Setting the hooks path to '/' shadows all other HTTP endpoints on the gateway.",
      remediation: 'Set hooks.path to a specific path like "/hooks"',
    });
  }

  // Logging redaction off
  if (config.logging?.redactSensitive === "off") {
    findings.push({
      checkId: "logging.redact_off",
      severity: "warn",
      title: "Tool output redaction is disabled",
      detail:
        "Sensitive data in tool outputs will be logged without redaction.",
      remediation: 'Set logging.redactSensitive to "tools"',
    });
  }

  // Tailscale funnel
  if (config.gateway?.tailscale?.mode === "funnel") {
    findings.push({
      checkId: "gateway.tailscale_funnel",
      severity: "critical",
      title: "Tailscale Funnel exposes agent to the public internet",
      detail:
        "Tailscale Funnel mode makes your agent accessible to anyone on the internet.",
      remediation:
        'Set gateway.tailscale.mode to "serve" (tailnet-only) or "off"',
    });
  }

  // Control UI insecure auth
  if (config.gateway?.controlUi?.allowInsecureAuth) {
    findings.push({
      checkId: "gateway.control_ui.insecure_auth",
      severity: "critical",
      title: "Control UI allows insecure HTTP authentication",
      detail:
        "The Control UI accepts authentication over unencrypted HTTP connections.",
      remediation: "Set gateway.controlUi.allowInsecureAuth to false",
    });
  }

  // Control UI device auth disabled
  if (config.gateway?.controlUi?.dangerouslyDisableDeviceAuth) {
    findings.push({
      checkId: "gateway.control_ui.device_auth_disabled",
      severity: "critical",
      title: "Control UI device authentication is disabled",
      detail:
        "Anyone who can reach the gateway can access the Control UI without device verification.",
      remediation:
        "Set gateway.controlUi.dangerouslyDisableDeviceAuth to false",
    });
  }

  return findings;
}
