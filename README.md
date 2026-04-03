# AgentArmor

Security scanner for AI agents. One command. A score out of 100. Plain-English explanations of what's wrong and how to fix it.

Currently supports [OpenClaw](https://github.com/openclaw/openclaw). Designed to support more agent types.

## Why

AI agents run with real permissions — they read your messages, execute commands, browse the web, and talk to APIs. A misconfigured agent is an open door.

OpenClaw has solid security primitives built in, but they're scattered across multiple commands and the output is raw. AgentArmor pulls it all together: runs the checks, maps every finding to the [MITRE ATLAS](https://atlas.mitre.org/) threat model, explains the blast radius in plain English, and gives you a single number you can track.

## Quick Start

```
npx agentarmor-cli scan
```

That's it. AgentArmor auto-detects your OpenClaw installation and scans it.

## What You Get

```
AgentArmor v0.1.0 — openclaw v2026.2.13

Score: 62/100 (D — Significant Risk) [capped: critical finding in gateway-exposure]

  Gateway Exposure     ................ 5/25  [2 critical]
  Sandbox Isolation    ............... 20/20
  Secrets              ............... 10/15  [1 warn]
  File Permissions     ............... 10/10
  Channel Access       ................ 4/10  [1 critical]
  Supply Chain         ................. 3/8  [2 warn]
  Browser Control      ................. 0/5  [1 critical]
  Hooks & Webhooks     ................. 3/3
  Elevated Exec        ................. 2/2
  Runtime Config       ................. 2/2

CRITICAL (3)

  gateway.bind_no_auth
    Gateway binds beyond loopback without authentication
    Blast radius: Anyone on your local network can fully control
                  your agent — read messages, execute commands,
                  and exfiltrate data.
    Fix: openclaw config set gateway.bind loopback

  channels.discord.dm.open
    Discord DMs are open to anyone
    Blast radius: Any Discord user who knows your bot can send
                  commands to your agent, including triggering
                  tool execution.
    Fix: openclaw configure  (set up pairing/allowlist)

  browser.control_no_auth
    Browser control endpoints have no authentication
    Blast radius: Any process on localhost can take full control
                  of your browser session — read cookies, navigate
                  pages, execute JavaScript.
    Fix: openclaw doctor --fix
```

Every finding tells you three things:

1. **What's wrong** — the specific misconfiguration
2. **Blast radius** — what an attacker can actually do, in plain English
3. **How to fix it** — a command you can copy and paste

## Install

```bash
# Run without installing
npx agentarmor-cli scan

# Or install globally
npm install -g agentarmor-cli
```

Requires Node.js 18+.

## Commands

### Scan

```bash
# Basic scan
agentarmor scan

# Include runtime probes (requires running gateway)
agentarmor scan --deep

# JSON output (for scripts and CI)
agentarmor scan --json

# Show all findings including info-level
agentarmor scan --verbose

# Fail CI if score drops below threshold
agentarmor scan --fail-below 70
```

### Fix

```bash
# See what would be fixed
agentarmor fix --dry-run

# Apply safe fixes
agentarmor fix
```

### Explain

```bash
# Deep-dive on a specific finding
agentarmor explain gateway.bind_no_auth
```

Output:

```
  Gateway binds beyond loopback without authentication
  Check ID: gateway.bind_no_auth
  Severity: CRITICAL
  Category: gateway-exposure
  MITRE ATLAS: T-ACCESS-001

  Gateway bind is set to "lan" but no authentication is configured.

  Blast Radius:
  Anyone on your local network can fully control your agent — read
  all messages, execute commands, trigger tools, and exfiltrate data.

  Fix:
  Set gateway.auth.mode to "token" or change gateway.bind to "loopback"
```

## How Scoring Works

AgentArmor starts at 100 and deducts points based on findings. Each finding belongs to one of 10 categories, weighted by real-world risk:

| Category | Weight | What it checks |
|---|---|---|
| Gateway Exposure | 25% | Network binding, authentication, Tailscale exposure |
| Sandbox Isolation | 20% | Sandbox mode, tool policies, model risk |
| Secrets | 15% | Plaintext tokens, credential hygiene |
| File Permissions | 10% | Config/state directory permissions |
| Channel Access | 10% | DM policies, slash command restrictions |
| Supply Chain | 8% | Installed skills and plugin safety |
| Browser Control | 5% | CDP authentication, remote connections |
| Hooks & Webhooks | 3% | Token strength, session key policies |
| Elevated Exec | 2% | Dangerous command allowlists |
| Runtime Config | 2% | Logging, model hygiene |

Weights are calibrated against OpenClaw's [MITRE ATLAS threat model](https://docs.openclaw.ai/security/THREAT-MODEL-ATLAS) and real CVE history.

**Grades:** A (90-100) · B (75-89) · C (60-74) · D (40-59) · F (0-39)

**Grade caps:** Critical findings cap the grade regardless of numeric score. Any critical caps at C. A critical in gateway exposure or sandbox isolation caps at D. Three or more criticals cap at F. A security tool that gives you an A while your gateway is wide open would be lying.

## How It Works

AgentArmor doesn't reinvent the wheel. It runs OpenClaw's own security commands and adds value on top:

```
openclaw security audit --json  ─┐
openclaw secrets audit --json   ─┼─▶ Normalize ─▶ Enrich ─▶ Score ─▶ Report
openclaw sandbox explain --json ─┘        │
                                     blast radius
                                     MITRE ATLAS mapping
                                     category + weight
```

If the OpenClaw CLI isn't available, AgentArmor falls back to reading `~/.openclaw/openclaw.json` directly and runs a subset of config-based checks. The score shows coverage percentage so you know how complete the scan was.

## CI Integration

```yaml
# GitHub Actions
- name: Security scan
  run: npx agentarmor-cli scan --fail-below 70 --json
```

Exit codes:
- `0` — scan complete
- `1` — scan failed (couldn't run)
- `2` — score below `--fail-below` threshold

JSON goes to stdout, warnings go to stderr. Pipe-friendly:

```bash
agentarmor scan --json | jq .score
```

## Contributing

AgentArmor is open source under the MIT license. Contributions welcome.

The most impactful way to contribute is adding to the **enrichment map** — the file that maps OpenClaw check IDs to blast radius descriptions and MITRE ATLAS references. See `src/scanners/openclaw/enrichment-map.ts`.

## License

MIT
