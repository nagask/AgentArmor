import type { AgentScanner } from "../core/types.js";
import { OpenClawScanner } from "./openclaw/index.js";

export class ScannerRegistry {
  private scanners: AgentScanner[] = [];

  register(scanner: AgentScanner): void {
    this.scanners.push(scanner);
  }

  async detectScanner(): Promise<AgentScanner | null> {
    for (const scanner of this.scanners) {
      const result = await scanner.detect();
      if (result.detected) {
        return scanner;
      }
    }
    return null;
  }

  getById(id: string): AgentScanner | undefined {
    return this.scanners.find((s) => s.id === id);
  }
}

let registry: ScannerRegistry | null = null;

export function getRegistry(): ScannerRegistry {
  if (!registry) {
    registry = new ScannerRegistry();
    registry.register(new OpenClawScanner());
  }
  return registry;
}
