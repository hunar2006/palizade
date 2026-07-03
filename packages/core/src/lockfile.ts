import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { LockStatus } from "@palizade/policy";
import { hashDescriptor, hashTool, stableStringify } from "./canonical.js";
import type { McpTool } from "./mcp.js";

export interface ToolLockEntry {
  hash: string;
  approvedAt: string;
}

export interface ServerLock {
  tools: Record<string, ToolLockEntry>;
  prompts?: Record<string, ToolLockEntry>;
  resources?: Record<string, ToolLockEntry>;
  resourceTemplates?: Record<string, ToolLockEntry>;
  capabilities?: ToolLockEntry;
  upstream?: ToolLockEntry;
}

export interface PalizadeLock {
  version: 1;
  servers: Record<string, ServerLock>;
}

export interface ToolLockCheck {
  tool: string;
  hash: string;
  status: LockStatus;
  kind?: string;
}

export class LockfileStore {
  constructor(private readonly path: string) {}

  async read(): Promise<PalizadeLock> {
    try {
      const raw = await readFile(this.path, "utf8");
      return JSON.parse(raw) as PalizadeLock;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { version: 1, servers: {} };
      }
      throw error;
    }
  }

  async write(lock: PalizadeLock): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, `${stableStringify(lock)}\n`, "utf8");
  }

  async checkTools(serverName: string, tools: McpTool[]): Promise<ToolLockCheck[]> {
    const lock = await this.read();
    const serverLock = lock.servers[serverName];
    return tools.map((tool) => {
      const hash = hashTool(tool);
      const existing = serverLock?.tools[tool.name];
      return {
        tool: tool.name,
        hash,
        status: existing ? existing.hash === hash ? "approved" : "changed" : serverLock ? "new" : "missing"
      };
    });
  }

  async checkDescriptors(serverName: string, kind: "prompts" | "resources" | "resourceTemplates", descriptors: unknown[], nameOf: (descriptor: unknown) => string): Promise<ToolLockCheck[]> {
    const lock = await this.read();
    const serverLock = lock.servers[serverName];
    const bucket = serverLock?.[kind];
    return descriptors.map((descriptor) => {
      const name = nameOf(descriptor);
      const hash = hashDescriptor(descriptor);
      const existing = bucket?.[name];
      return {
        tool: name,
        hash,
        kind,
        status: existing ? existing.hash === hash ? "approved" : "changed" : serverLock ? "new" : "missing"
      };
    });
  }

  async checkCapabilities(serverName: string, capabilities: unknown): Promise<ToolLockCheck> {
    const lock = await this.read();
    const serverLock = lock.servers[serverName];
    const hash = hashDescriptor(capabilities ?? {});
    const existing = serverLock?.capabilities;
    return {
      tool: "capabilities",
      hash,
      kind: "capabilities",
      status: existing ? existing.hash === hash ? "approved" : "changed" : serverLock ? "new" : "missing"
    };
  }

  async approveTools(serverName: string, tools: McpTool[]): Promise<ToolLockCheck[]> {
    const lock = await this.read();
    lock.servers[serverName] ??= { tools: {} };
    const now = new Date().toISOString();
    const checks: ToolLockCheck[] = [];
    for (const tool of tools) {
      const hash = hashTool(tool);
      lock.servers[serverName].tools[tool.name] = { hash, approvedAt: now };
      checks.push({ tool: tool.name, hash, status: "approved" });
    }
    await this.write(lock);
    return checks;
  }

  async approveDescriptors(serverName: string, kind: "prompts" | "resources" | "resourceTemplates", descriptors: unknown[], nameOf: (descriptor: unknown) => string): Promise<ToolLockCheck[]> {
    const lock = await this.read();
    lock.servers[serverName] ??= { tools: {} };
    lock.servers[serverName][kind] ??= {};
    const bucket = lock.servers[serverName][kind]!;
    const now = new Date().toISOString();
    const checks: ToolLockCheck[] = [];
    for (const descriptor of descriptors) {
      const name = nameOf(descriptor);
      const hash = hashDescriptor(descriptor);
      bucket[name] = { hash, approvedAt: now };
      checks.push({ tool: name, hash, kind, status: "approved" });
    }
    await this.write(lock);
    return checks;
  }
}
