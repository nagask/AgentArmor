export type Severity = "critical" | "warn" | "info";

export type CheckCategory =
  | "gateway-exposure"
  | "sandbox-isolation"
  | "secrets"
  | "permissions"
  | "channel-access"
  | "supply-chain"
  | "browser-control"
  | "hooks-webhooks"
  | "elevated-exec"
  | "runtime-config";

export const CATEGORY_WEIGHTS: Record<CheckCategory, number> = {
  "gateway-exposure": 25,
  "sandbox-isolation": 20,
  secrets: 15,
  permissions: 10,
  "channel-access": 10,
  "supply-chain": 8,
  "browser-control": 5,
  "hooks-webhooks": 3,
  "elevated-exec": 2,
  "runtime-config": 2,
};

export const CATEGORY_LABELS: Record<CheckCategory, string> = {
  "gateway-exposure": "Gateway Exposure",
  "sandbox-isolation": "Sandbox Isolation",
  secrets: "Secrets",
  permissions: "File Permissions",
  "channel-access": "Channel Access",
  "supply-chain": "Supply Chain",
  "browser-control": "Browser Control",
  "hooks-webhooks": "Hooks & Webhooks",
  "elevated-exec": "Elevated Exec",
  "runtime-config": "Runtime Config",
};

export interface Finding {
  checkId: string;
  category: CheckCategory;
  severity: Severity;
  title: string;
  detail: string;
  remediation?: string;
  blastRadius: string;
  atlasId?: string;
  source: "cli" | "config";
}

export interface CategoryScore {
  category: CheckCategory;
  label: string;
  weight: number;
  score: number;
  maxPoints: number;
  deducted: number;
  findings: { critical: number; warn: number; info: number };
}

export interface ScanResult {
  agent: string;
  version: string;
  timestamp: number;
  score: number;
  coverage: number;
  grade: string;
  gradeCapped: boolean;
  gradeCappedReason?: string;
  blockers: number;
  categories: CategoryScore[];
  findings: Finding[];
  warnings: string[];
}

export interface ScanOptions {
  deep?: boolean;
  json?: boolean;
  verbose?: boolean;
  timeout?: number;
  failBelow?: number;
  categories?: CheckCategory[];
}

export interface DetectionResult {
  detected: boolean;
  version?: string;
  binaryPath?: string;
  configPath?: string;
  stateDir?: string;
  error?: string;
}

export interface FixResult {
  checkId: string;
  applied: boolean;
  description: string;
  error?: string;
}

export interface AgentScanner {
  readonly id: string;
  readonly label: string;
  detect(): Promise<DetectionResult>;
  scan(options: ScanOptions): Promise<ScanResult>;
  fix?(findings: Finding[], dryRun: boolean): Promise<FixResult[]>;
}
