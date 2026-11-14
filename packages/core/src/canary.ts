import { createHash, randomBytes } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { expandCandidates } from "@palizade/taint";
import type { PalizadeConfig } from "./config.js";

/**
 * Canary secrets: fake credentials planted where an agent can read them (an .env file). Nothing
 * legitimate ever sends one anywhere, so a canary in an outbound call means something is
 * collecting secrets. Unlike fingerprints this works for short values and needs no source call.
 */
export interface Canary {
  name: string;
  value: string;
  file: string;
  createdAt: string;
}

export function canaryStorePath(config: Pick<PalizadeConfig, "stateDir">): string {
  return join(config.stateDir, "canaries.json");
}

/** Never throws: an unreadable store only means no canaries. */
export function readCanaries(config: Pick<PalizadeConfig, "stateDir">): Canary[] {
  try {
    const parsed: unknown = JSON.parse(readFileSync(canaryStorePath(config), "utf8"));
    return Array.isArray(parsed) ? parsed.filter((entry): entry is Canary => typeof entry?.value === "string" && entry.value.length >= 16) : [];
  } catch {
    return [];
  }
}

/** Appends `NAME=value` to the file (created if missing) and records the value in the state directory. */
export function plantCanary(config: Pick<PalizadeConfig, "stateDir">, file: string, name: string): Canary {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) throw new Error("The canary name must be a valid environment variable name.");
  const canary: Canary = { name, value: `${name.toLowerCase().slice(0, 3)}_${randomBytes(24).toString("hex")}`, file, createdAt: new Date().toISOString() };
  const existing = existsSync(file) ? readFileSync(file, "utf8") : "";
  if (new RegExp(`^${name}=`, "mu").test(existing)) throw new Error(`${file} already defines ${name}; choose another --name.`);
  mkdirSync(dirname(file), { recursive: true });
  appendFileSync(file, `${existing && !existing.endsWith("\n") ? "\n" : ""}${name}=${canary.value}\n`);
  mkdirSync(config.stateDir, { recursive: true });
  writeFileSync(canaryStorePath(config), `${JSON.stringify([...readCanaries(config), canary], null, 2)}\n`, { mode: 0o600 });
  return canary;
}

/** True when the text, or anything it decodes to (base64, hex, url encoding), contains a canary. */
export function containsCanary(text: string, canaries: Canary[], limits?: Parameters<typeof expandCandidates>[1]): boolean {
  if (canaries.length === 0 || !text) return false;
  // shortcut: a canary split across calls or reversed is missed; reuse the outbound window if that shows up.
  return expandCandidates(text, limits).some((candidate) => canaries.some((canary) => candidate.text.includes(canary.value)));
}

/**
 * Seal: hashes of the config and policy files, taken when the user ran `palizade seal`. A policy
 * that changes afterwards (a branch checkout, a script the agent wrote) makes hooks ask until the
 * user seals again. Opt in: without a seal file nothing is checked.
 */
export function sealPath(config: Pick<PalizadeConfig, "stateDir">): string {
  return join(config.stateDir, "seal.json");
}

function sha256File(path: string): string {
  return existsSync(path) ? createHash("sha256").update(readFileSync(path)).digest("hex") : "missing";
}

export function writeSeal(config: Pick<PalizadeConfig, "stateDir">, files: string[]): Record<string, string> {
  const seal = Object.fromEntries(files.map((file) => [file, sha256File(file)]));
  mkdirSync(config.stateDir, { recursive: true });
  writeFileSync(sealPath(config), `${JSON.stringify(seal, null, 2)}\n`, { mode: 0o600 });
  return seal;
}

/** Files whose content no longer matches the seal; empty when there is no seal. An unreadable seal counts as drift. */
export function sealDrift(config: Pick<PalizadeConfig, "stateDir">): string[] {
  const path = sealPath(config);
  if (!existsSync(path)) return [];
  try {
    const seal = JSON.parse(readFileSync(path, "utf8")) as Record<string, string>;
    return Object.entries(seal).filter(([file, hash]) => sha256File(file) !== hash).map(([file]) => file);
  } catch {
    return [path];
  }
}
