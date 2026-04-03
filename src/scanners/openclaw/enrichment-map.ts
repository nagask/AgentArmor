import type { CheckCategory } from "../../core/types.js";

export interface Enrichment {
  category: CheckCategory;
  blastRadius: string;
  atlasId?: string;
}

const DEFAULT_ENRICHMENT: Enrichment = {
  category: "runtime-config",
  blastRadius:
    "This check failed but AgentArmor doesn't have detailed context yet. Run 'openclaw security audit' for more info.",
};

/**
 * Static enrichment map: OpenClaw checkId → category, blast radius, ATLAS ID.
 * This is the core value-add of AgentArmor.
 */
const ENRICHMENT_MAP: Record<string, Enrichment> = {
  // ── Gateway Exposure ──────────────────────────────────────────────
  "gateway.bind_no_auth": {
    category: "gateway-exposure",
    blastRadius:
      "Anyone on your local network can fully control your agent — read all messages, execute commands, trigger tools, and exfiltrate data.",
    atlasId: "T-ACCESS-001",
  },
  "gateway.loopback_no_auth": {
    category: "gateway-exposure",
    blastRadius:
      "Any process on your machine (or any SSRF vulnerability) can take full control of your agent without authentication.",
    atlasId: "T-ACCESS-001",
  },
  "gateway.tailscale_funnel": {
    category: "gateway-exposure",
    blastRadius:
      "Your agent is exposed to the PUBLIC INTERNET via Tailscale Funnel. Anyone worldwide with the URL can interact with it.",
    atlasId: "T-RECON-001",
  },
  "gateway.tailscale_serve": {
    category: "gateway-exposure",
    blastRadius:
      "Your agent is exposed to your Tailscale network. Other devices on your tailnet can access it.",
  },
  "gateway.control_ui.insecure_auth": {
    category: "gateway-exposure",
    blastRadius:
      "The Control UI accepts authentication over unencrypted HTTP. Credentials can be sniffed by anyone on the network.",
    atlasId: "T-ACCESS-003",
  },
  "gateway.control_ui.device_auth_disabled": {
    category: "gateway-exposure",
    blastRadius:
      "Device authentication is disabled for the Control UI. Anyone who can reach the gateway can access the admin panel.",
    atlasId: "T-ACCESS-001",
  },
  "gateway.token_too_short": {
    category: "gateway-exposure",
    blastRadius:
      "A short gateway token is vulnerable to brute-force attacks, especially if the gateway is network-exposed.",
    atlasId: "T-ACCESS-003",
  },
  "gateway.trusted_proxies_missing": {
    category: "gateway-exposure",
    blastRadius:
      "Without trusted proxy configuration, the gateway may not correctly identify client IPs behind a reverse proxy.",
  },
  "gateway.http.session_key_override_enabled": {
    category: "gateway-exposure",
    blastRadius:
      "HTTP endpoints accept session key overrides. An attacker could hijack or impersonate another user's session.",
    atlasId: "T-ACCESS-002",
  },
  "gateway.probe_failed": {
    category: "gateway-exposure",
    blastRadius:
      "The gateway probe failed during deep scan. This may indicate the gateway is not running or is misconfigured.",
  },

  // ── Sandbox Isolation ─────────────────────────────────────────────
  "models.small_params": {
    category: "sandbox-isolation",
    blastRadius:
      "Small models (≤300B params) are more susceptible to prompt injection. Without sandboxing, a hijacked model can execute arbitrary commands.",
    atlasId: "T-EXEC-001",
  },

  // ── Secrets ───────────────────────────────────────────────────────
  "config.secrets.gateway_password_in_config": {
    category: "secrets",
    blastRadius:
      "Your gateway password is stored in plaintext in the config file. Anyone who can read the file has full gateway access.",
    atlasId: "T-ACCESS-003",
  },
  "config.secrets.hooks_token_in_config": {
    category: "secrets",
    blastRadius:
      "Your hooks token is stored in the config file. Consider using environment variable references (${VAR_NAME}) instead.",
  },

  // ── File Permissions ──────────────────────────────────────────────
  "fs.state_dir.symlink": {
    category: "permissions",
    blastRadius:
      "The state directory is a symlink. An attacker could redirect it to capture or tamper with agent state.",
  },
  "fs.state_dir.perms_world_writable": {
    category: "permissions",
    blastRadius:
      "The state directory is world-writable. ANY user on this machine can modify your agent's state, sessions, and credentials.",
    atlasId: "T-PERSIST-003",
  },
  "fs.state_dir.perms_group_writable": {
    category: "permissions",
    blastRadius:
      "The state directory is group-writable. Other users in the same group can modify agent state.",
  },
  "fs.state_dir.perms_readable": {
    category: "permissions",
    blastRadius:
      "The state directory is readable by other users. They can view agent state, session data, and potentially credentials.",
  },
  "fs.config.symlink": {
    category: "permissions",
    blastRadius:
      "The config file is a symlink. An attacker could redirect it to inject malicious configuration.",
  },
  "fs.config.perms_writable": {
    category: "permissions",
    blastRadius:
      "The config file is writable by other users. They can modify your agent's configuration — change gateway auth, add elevated permissions, or disable security features.",
    atlasId: "T-PERSIST-003",
  },
  "fs.config.perms_world_readable": {
    category: "permissions",
    blastRadius:
      "The config file is world-readable. Any user on this machine can read your gateway tokens, webhook secrets, and API keys.",
    atlasId: "T-ACCESS-003",
  },
  "fs.config.perms_group_readable": {
    category: "permissions",
    blastRadius:
      "The config file is readable by users in the same group. They can view gateway tokens and webhook secrets.",
  },
  "fs.synced_dir": {
    category: "permissions",
    blastRadius:
      "Your state or config path is inside a cloud-synced folder (iCloud/Dropbox/OneDrive). Tokens and credentials may be uploaded to the cloud.",
    atlasId: "T-EXFIL-001",
  },
  "fs.config_include.perms_writable": {
    category: "permissions",
    blastRadius:
      "A config include file is writable by other users. They can inject malicious configuration into your agent.",
  },
  "fs.config_include.perms_world_readable": {
    category: "permissions",
    blastRadius:
      "A config include file is world-readable. Secrets in included config files are exposed to all users.",
  },
  "fs.config_include.perms_group_readable": {
    category: "permissions",
    blastRadius:
      "A config include file is readable by users in the same group.",
  },
  "fs.credentials_dir.perms_writable": {
    category: "permissions",
    blastRadius:
      "The credentials directory is writable by other users. They can inject or modify stored credentials.",
  },
  "fs.credentials_dir.perms_readable": {
    category: "permissions",
    blastRadius:
      "The credentials directory is readable by other users. They can access stored authentication credentials.",
  },
  "fs.auth_profiles.perms_writable": {
    category: "permissions",
    blastRadius:
      "auth-profiles.json is writable by other users. They can modify authentication profiles.",
  },
  "fs.auth_profiles.perms_readable": {
    category: "permissions",
    blastRadius:
      "auth-profiles.json is readable by other users. Authentication profile data may be exposed.",
  },
  "fs.sessions_store.perms_readable": {
    category: "permissions",
    blastRadius:
      "sessions.json is readable by other users. Session data and conversation history may be exposed.",
  },
  "fs.log_file.perms_readable": {
    category: "permissions",
    blastRadius:
      "The log file is readable by other users. Logs may contain sensitive tool outputs or message content.",
  },

  // ── Channel Access ────────────────────────────────────────────────
  "channels.discord.dm.open": {
    category: "channel-access",
    blastRadius:
      "Discord DMs are open to ANYONE. Any Discord user who can message your bot can send commands to your agent.",
    atlasId: "T-ACCESS-002",
  },
  "channels.discord.dm.open_invalid": {
    category: "channel-access",
    blastRadius:
      "Discord DM config is inconsistent. DMs may be unintentionally open.",
  },
  "channels.discord.dm.disabled": {
    category: "channel-access",
    blastRadius:
      "Discord DMs are disabled. This is an informational note, not a security issue.",
  },
  "channels.discord.dm.scope_main_multiuser": {
    category: "channel-access",
    blastRadius:
      "Discord DMs share the main agent session. Different users' messages will be in the same context — potential information leakage between users.",
    atlasId: "T-DISC-001",
  },
  "channels.discord.commands.native.unrestricted": {
    category: "channel-access",
    blastRadius:
      "Discord slash commands are unrestricted. Any user in any server can trigger agent commands, including tool execution.",
    atlasId: "T-ACCESS-002",
  },
  "channels.discord.commands.native.no_allowlists": {
    category: "channel-access",
    blastRadius:
      "Discord slash commands have no allowlists configured. Consider restricting by guild or user.",
  },
  "channels.slack.commands.slash.useAccessGroups_off": {
    category: "channel-access",
    blastRadius:
      "Slack slash commands bypass access groups. Any Slack user can trigger agent commands.",
    atlasId: "T-ACCESS-002",
  },
  "channels.slack.commands.slash.no_allowlists": {
    category: "channel-access",
    blastRadius:
      "Slack slash commands have no allowlists. Consider restricting by channel or user.",
  },
  "channels.telegram.groups.allowFrom.wildcard": {
    category: "channel-access",
    blastRadius:
      "Telegram group commands accept messages from ANY sender. Anyone in an allowed group can control your agent.",
    atlasId: "T-ACCESS-002",
  },
  "channels.telegram.groups.allowFrom.missing": {
    category: "channel-access",
    blastRadius:
      "Telegram group commands have no sender allowlist. Anyone in the group can send commands.",
    atlasId: "T-ACCESS-002",
  },

  // ── Supply Chain ──────────────────────────────────────────────────
  "plugins.extensions_no_allowlist": {
    category: "supply-chain",
    blastRadius:
      "Plugin extensions exist but no allowlist is configured. Unvetted plugins can run with full agent privileges.",
    atlasId: "T-PERSIST-001",
  },
  "plugins.code_safety": {
    category: "supply-chain",
    blastRadius:
      "A plugin contains suspicious code patterns (exec, eval, crypto mining, or env harvesting). It may be malicious.",
    atlasId: "T-PERSIST-001",
  },
  "plugins.code_safety.scan_failed": {
    category: "supply-chain",
    blastRadius:
      "Plugin code safety scan failed. Plugin code could not be inspected for malicious patterns.",
  },
  "plugins.code_safety.entry_path": {
    category: "supply-chain",
    blastRadius:
      "A plugin has a hidden or node_modules entry path, which may be an attempt to evade inspection.",
  },
  "plugins.code_safety.entry_escape": {
    category: "supply-chain",
    blastRadius:
      "A plugin has an entry path that traverses outside its expected directory. This is a path traversal attack.",
    atlasId: "T-PERSIST-001",
  },
  "skills.code_safety": {
    category: "supply-chain",
    blastRadius:
      "An installed skill contains suspicious code patterns. It may execute arbitrary commands, harvest credentials, or exfiltrate data.",
    atlasId: "T-PERSIST-001",
  },
  "skills.code_safety.scan_failed": {
    category: "supply-chain",
    blastRadius:
      "Skill code safety scan failed. Skill code could not be inspected for malicious patterns.",
  },

  // ── Browser Control ───────────────────────────────────────────────
  "browser.control_invalid_config": {
    category: "browser-control",
    blastRadius:
      "Browser control configuration looks invalid. The browser may not function as expected.",
  },
  "browser.control_no_auth": {
    category: "browser-control",
    blastRadius:
      "Browser control endpoints have no authentication. Any process on localhost (or any SSRF) can take full control of your browser session — read cookies, navigate pages, execute JavaScript.",
    atlasId: "T-EXEC-001",
  },
  "browser.remote_cdp_http": {
    category: "browser-control",
    blastRadius:
      "Remote Chrome DevTools Protocol connection uses HTTP instead of HTTPS. Browser control traffic can be intercepted.",
  },

  // ── Hooks & Webhooks ──────────────────────────────────────────────
  "hooks.token_too_short": {
    category: "hooks-webhooks",
    blastRadius:
      "A short webhook token is vulnerable to brute-force. Attackers could forge webhook payloads to trigger your agent.",
  },
  "hooks.token_reuse_gateway_token": {
    category: "hooks-webhooks",
    blastRadius:
      "The hooks token reuses the gateway token. Compromising one exposes both — webhook forgery AND gateway access.",
    atlasId: "T-ACCESS-003",
  },
  "hooks.path_root": {
    category: "hooks-webhooks",
    blastRadius:
      "Hooks base path is '/', shadowing ALL other HTTP endpoints. This breaks gateway functionality and may expose unintended endpoints to webhook callers.",
  },
  "hooks.default_session_key_unset": {
    category: "hooks-webhooks",
    blastRadius:
      "No default session key for hooks. Webhook payloads without an explicit session key will use an unpredictable session.",
  },
  "hooks.request_session_key_enabled": {
    category: "hooks-webhooks",
    blastRadius:
      "External webhook payloads can override the session key. An attacker could hijack or impersonate sessions via crafted webhooks.",
    atlasId: "T-ACCESS-002",
  },
  "hooks.request_session_key_prefixes_missing": {
    category: "hooks-webhooks",
    blastRadius:
      "Session key override is enabled without prefix restrictions. Any session key can be specified in webhook payloads.",
    atlasId: "T-ACCESS-002",
  },

  // ── Elevated Exec ─────────────────────────────────────────────────
  // Dynamic checkIds: tools.elevated.allowFrom.{provider}.wildcard
  // and tools.elevated.allowFrom.{provider}.large
  // Handled via prefix matching in getEnrichment()

  // ── Runtime Config ────────────────────────────────────────────────
  "logging.redact_off": {
    category: "runtime-config",
    blastRadius:
      "Tool output redaction is disabled. Sensitive data (API keys, passwords, PII) in tool outputs will be logged in full.",
  },
  "summary.attack_surface": {
    category: "runtime-config",
    blastRadius:
      "This is an informational summary of your agent's attack surface, not a specific security issue.",
  },
  "security.exposure.open_groups_with_elevated": {
    category: "elevated-exec",
    blastRadius:
      "Open group policy combined with elevated tool permissions. Anyone in any group can trigger elevated (dangerous) commands on your agent.",
    atlasId: "T-IMPACT-001",
  },
  "models.legacy": {
    category: "runtime-config",
    blastRadius:
      "Legacy models (GPT-3.5, Claude 2, old GPT-4 snapshots) may have known vulnerabilities and weaker instruction following.",
  },
  "models.weak_tier": {
    category: "runtime-config",
    blastRadius:
      "Weak-tier models are more susceptible to prompt injection and may not follow security instructions reliably.",
    atlasId: "T-EXEC-001",
  },
};

/**
 * Prefix patterns for dynamic checkIds (e.g., tools.elevated.allowFrom.discord.wildcard)
 */
const PREFIX_ENRICHMENTS: Array<{ prefix: string; enrichment: Enrichment }> = [
  {
    prefix: "tools.elevated.allowFrom.",
    enrichment: {
      category: "elevated-exec",
      blastRadius:
        "The elevated exec allowlist is too permissive. Users matching this allowlist can execute dangerous system commands through your agent.",
      atlasId: "T-IMPACT-001",
    },
  },
  {
    prefix: "channels.slack.dm.",
    enrichment: {
      category: "channel-access",
      blastRadius:
        "Slack DM policy may be too permissive. Review who can send direct messages to your agent.",
      atlasId: "T-ACCESS-002",
    },
  },
  {
    prefix: "channels.whatsapp.dm.",
    enrichment: {
      category: "channel-access",
      blastRadius:
        "WhatsApp DM policy may be too permissive. Any WhatsApp user who knows your bot's number could send commands.",
      atlasId: "T-ACCESS-002",
    },
  },
  {
    prefix: "channels.",
    enrichment: {
      category: "channel-access",
      blastRadius:
        "A channel security check flagged a potential issue. Review your channel access policies.",
    },
  },
];

export function getEnrichment(checkId: string): Enrichment {
  // Exact match first
  const exact = ENRICHMENT_MAP[checkId];
  if (exact) return exact;

  // Prefix match for dynamic checkIds
  for (const { prefix, enrichment } of PREFIX_ENRICHMENTS) {
    if (checkId.startsWith(prefix)) return enrichment;
  }

  return DEFAULT_ENRICHMENT;
}

/**
 * Returns the total number of known checks (for coverage calculation).
 * This is an approximation — dynamic checks vary per installation.
 */
export const KNOWN_CHECK_COUNT = Object.keys(ENRICHMENT_MAP).length;
