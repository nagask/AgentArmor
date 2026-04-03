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
    allowedSessionKeyPrefixes?: string[];
  };
  browser?: {
    enabled?: boolean;
    evaluateEnabled?: boolean;
  };
  logging?: {
    redactSensitive?: string;
  };
  tools?: {
    elevated?: {
      enabled?: boolean;
      allowFrom?: Record<string, string[]>;
    };
  };
  channels?: Record<string, {
    dm?: {
      policy?: string;
    };
    groupPolicy?: string;
    [key: string]: unknown;
  }>;
  [key: string]: unknown;
}

export interface ConfigCheckResult {
  findings: RawFinding[];
  checksRun: number;
}

export async function readConfig(configPath: string): Promise<OpenClawConfig> {
  const content = await readFile(configPath, "utf-8");
  if (!content.trim()) {
    throw new Error("Config file is empty");
  }
  return JSON5.parse(content) as OpenClawConfig;
}

/**
 * Run config-based checks when CLI is unavailable.
 * Returns findings and the number of checks executed.
 */
export function runConfigChecks(config: OpenClawConfig): ConfigCheckResult {
  const findings: RawFinding[] = [];
  let checksRun = 0;

  // ── Gateway checks ────────────────────────────────────────────

  // Gateway bind without auth
  checksRun++;
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

  // Gateway token too short
  checksRun++;
  if (
    config.gateway?.auth?.token &&
    !config.gateway.auth.token.includes("${") &&
    config.gateway.auth.token.length < 24
  ) {
    findings.push({
      checkId: "gateway.token_too_short",
      severity: "warn",
      title: "Gateway token is too short",
      detail: `Gateway token is ${config.gateway.auth.token.length} characters. Minimum recommended: 24.`,
      remediation: "Generate a longer token: openssl rand -hex 24",
    });
  }

  // Gateway password in config
  checksRun++;
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

  // Tailscale funnel
  checksRun++;
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
  checksRun++;
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
  checksRun++;
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

  // ── Hooks checks ──────────────────────────────────────────────

  // Hooks token in config
  checksRun++;
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

  // Hooks token too short
  checksRun++;
  if (
    config.hooks?.token &&
    !config.hooks.token.includes("${") &&
    config.hooks.token.length < 24
  ) {
    findings.push({
      checkId: "hooks.token_too_short",
      severity: "warn",
      title: "Hooks token is too short",
      detail: `Hooks token is ${config.hooks.token.length} characters. Minimum recommended: 24.`,
      remediation: "Generate a longer token: openssl rand -hex 24",
    });
  }

  // Hooks token reuses gateway token
  checksRun++;
  if (
    config.hooks?.token &&
    config.gateway?.auth?.token &&
    config.hooks.token === config.gateway.auth.token
  ) {
    findings.push({
      checkId: "hooks.token_reuse_gateway_token",
      severity: "warn",
      title: "Hooks token reuses the gateway token",
      detail:
        "The hooks token is the same as the gateway token. Compromising one exposes both.",
      remediation: "Use separate tokens for hooks and gateway auth",
    });
  }

  // Hooks path root
  checksRun++;
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

  // Hooks default session key unset
  checksRun++;
  if (config.hooks?.enabled && !config.hooks.defaultSessionKey) {
    findings.push({
      checkId: "hooks.default_session_key_unset",
      severity: "warn",
      title: "Hooks default session key is not configured",
      detail:
        "Webhook payloads without an explicit session key will use an unpredictable session.",
      remediation: "Set hooks.defaultSessionKey to a stable identifier",
    });
  }

  // Hooks request session key override
  checksRun++;
  if (config.hooks?.allowRequestSessionKey) {
    const hasPrefixes =
      config.hooks.allowedSessionKeyPrefixes &&
      config.hooks.allowedSessionKeyPrefixes.length > 0;

    const isRemotelyExposed =
      config.gateway?.bind !== "loopback" &&
      config.gateway?.bind !== undefined;

    if (!hasPrefixes) {
      findings.push({
        checkId: "hooks.request_session_key_prefixes_missing",
        severity: isRemotelyExposed ? "critical" : "warn",
        title: "Session key override enabled without prefix restrictions",
        detail:
          "External webhook payloads can specify any session key without restrictions.",
        remediation:
          "Set hooks.allowedSessionKeyPrefixes to limit which session keys can be overridden",
      });
    }
  }

  // ── Browser checks ────────────────────────────────────────────

  // Browser control without auth
  checksRun++;
  if (config.browser?.enabled) {
    // Browser is enabled — if gateway has no auth, browser control is exposed
    const hasAuth = !!(config.gateway?.auth?.mode || config.gateway?.auth?.token);
    if (!hasAuth) {
      findings.push({
        checkId: "browser.control_no_auth",
        severity: "critical",
        title: "Browser control enabled without gateway authentication",
        detail:
          "Browser control is enabled but the gateway has no authentication configured.",
        remediation: 'Set gateway.auth.mode to "token"',
      });
    }
  }

  // ── Logging checks ────────────────────────────────────────────

  checksRun++;
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

  // ── Channel checks ────────────────────────────────────────────

  if (config.channels) {
    for (const [provider, channelConfig] of Object.entries(config.channels)) {
      if (!channelConfig || typeof channelConfig !== "object") continue;

      checksRun++;
      // Open DM policy
      if (channelConfig.dm?.policy === "open") {
        findings.push({
          checkId: `channels.${provider}.dm.open`,
          severity: "critical",
          title: `${capitalize(provider)} DMs are open to anyone`,
          detail: `Any ${capitalize(provider)} user can send direct messages to your agent.`,
          remediation: `Configure a DM allowlist for ${provider}`,
        });
      }

      checksRun++;
      // Open group policy
      if (channelConfig.groupPolicy === "open") {
        findings.push({
          checkId: `channels.${provider}.group.open`,
          severity: "warn",
          title: `${capitalize(provider)} group policy is open`,
          detail: `Any group/channel can interact with your agent on ${capitalize(provider)}.`,
          remediation: `Set ${provider}.groupPolicy to "allowlist"`,
        });
      }
    }
  }

  // ── Elevated + open group exposure ────────────────────────────

  checksRun++;
  if (config.tools?.elevated?.enabled) {
    const hasOpenGroup = config.channels
      ? Object.values(config.channels).some(
          (ch) => ch && typeof ch === "object" && ch.groupPolicy === "open"
        )
      : false;

    if (hasOpenGroup) {
      findings.push({
        checkId: "security.exposure.open_groups_with_elevated",
        severity: "critical",
        title: "Open group policy with elevated tools enabled",
        detail:
          "Open group policies combined with elevated tool permissions allow anyone in any group to trigger dangerous commands.",
        remediation:
          'Set groupPolicy to "allowlist" or disable tools.elevated',
      });
    }
  }

  return { findings, checksRun };
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
