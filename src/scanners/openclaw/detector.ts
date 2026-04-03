import { execFile } from "node:child_process";
import { access, stat } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { DetectionResult } from "../../core/types.js";

function execPromise(
  cmd: string,
  args: string[],
  timeout = 10_000
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      cmd,
      args,
      { timeout, encoding: "utf-8" },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
        } else {
          resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
        }
      }
    );
  });
}

async function findBinary(): Promise<string | null> {
  try {
    const { stdout } = await execPromise("which", ["openclaw"]);
    if (stdout) return stdout;
  } catch {
    // not in PATH
  }

  // Check common locations
  const candidates = [
    join(homedir(), ".local", "bin", "openclaw"),
    "/usr/local/bin/openclaw",
    join(homedir(), "Library", "pnpm", "openclaw"),
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // not found
    }
  }

  return null;
}

async function getVersion(binaryPath: string): Promise<string | undefined> {
  try {
    const { stdout } = await execPromise(binaryPath, ["--version"]);
    // Expect something like "openclaw v2026.2.13" or just "2026.2.13"
    const match = stdout.match(/(\d+\.\d+\.\d+)/);
    return match?.[1];
  } catch {
    return undefined;
  }
}

function getDefaultStateDir(): string {
  return join(homedir(), ".openclaw");
}

function getDefaultConfigPath(): string {
  return join(getDefaultStateDir(), "openclaw.json");
}

export async function detectOpenClaw(): Promise<DetectionResult> {
  const stateDir = getDefaultStateDir();
  const configPath = getDefaultConfigPath();

  // Check if state dir exists
  let stateDirExists = false;
  try {
    const s = await stat(stateDir);
    stateDirExists = s.isDirectory();
  } catch {
    // doesn't exist
  }

  // Check if config exists
  let configExists = false;
  try {
    await access(configPath);
    configExists = true;
  } catch {
    // doesn't exist
  }

  // Find binary
  const binaryPath = await findBinary();

  // Get version if binary found
  const version = binaryPath ? await getVersion(binaryPath) : undefined;

  // Detected if either binary or config exists
  const detected = binaryPath !== null || configExists;

  if (!detected) {
    return {
      detected: false,
      error:
        "OpenClaw not detected. No binary in PATH and no config at " +
        configPath,
    };
  }

  return {
    detected: true,
    version,
    binaryPath: binaryPath ?? undefined,
    configPath: configExists ? configPath : undefined,
    stateDir: stateDirExists ? stateDir : undefined,
  };
}
