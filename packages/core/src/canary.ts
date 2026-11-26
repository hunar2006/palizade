import { createHash, randomBytes, randomUUID } from "node:crypto";
import { appendFileSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { parseEnv } from "node:util";
import { expandCandidates } from "@palizade/taint";
import type { PalizadeConfig } from "./config.js";
import { resolveArgumentPath } from "./protected-paths.js";

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

/** Loads planted canaries; returns an empty list only when the store file does not exist. */
export function readCanaries(config: Pick<PalizadeConfig, "stateDir">): Canary[] {
  const path = canaryStorePath(config);
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw new Error(`Canary store ${path} could not be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Canary store ${path} is corrupt: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`Canary store ${path} is corrupt: expected a JSON array.`);
  }
  const canaries: Canary[] = [];
  for (const entry of parsed) {
    if (!entry || typeof entry !== "object" || typeof (entry as { value?: unknown }).value !== "string" || (entry as { value: string }).value.length < 16) {
      throw new Error(`Canary store ${path} is corrupt: invalid canary entry.`);
    }
    canaries.push(entry as Canary);
  }
  return canaries;
}

/** Appends `NAME=value` to the file (created if missing) and records the value in the state directory. */
export function plantCanary(config: Pick<PalizadeConfig, "stateDir">, file: string, name: string): Canary {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) throw new Error("The canary name must be a valid environment variable name.");
  const canary: Canary = { name, value: `${name.toLowerCase().slice(0, 3)}_${randomBytes(24).toString("hex")}`, file, createdAt: new Date().toISOString() };
  const existing = existsSync(file) ? readFileSync(file, "utf8") : "";
  if (Object.hasOwn(parseEnv(existing.replace(/^\uFEFF/u, "")), name)) {
    throw new Error(`${file} already defines ${name}; choose another --name.`);
  }
  const existingCanaries = readCanaries(config);
  mkdirSync(dirname(file), { recursive: true });
  appendFileSync(file, `${existing && !existing.endsWith("\n") ? "\n" : ""}${name}=${canary.value}\n`);
  mkdirSync(config.stateDir, { recursive: true });
  writeFileSync(canaryStorePath(config), `${JSON.stringify([...existingCanaries, canary], null, 2)}\n`, { mode: 0o600 });
  return canary;
}

/** True when the text, or anything it decodes to (base64, hex, url encoding), contains a canary. */
export function containsCanary(text: string, canaries: Canary[], limits?: Parameters<typeof expandCandidates>[1]): boolean {
  if (canaries.length === 0 || !text) return false;
  // shortcut: a canary split across calls or reversed is missed; reuse the outbound window if that shows up.
  return expandCandidates(text, limits).some((candidate) => {
    const lower = candidate.text.toLowerCase();
    return canaries.some((canary) => lower.includes(canary.value.toLowerCase()));
  });
}

type SealConfig = Pick<PalizadeConfig, "stateDir"> & Partial<Pick<PalizadeConfig, "egress" | "lockfile">>;

export function defaultSealPath(configPath: string): string {
  return join(dirname(resolve(configPath)), ".palizade", "seal.json");
}

/** The environment override must come from the operator, outside the protected project. */
export function sealPath(config: SealConfig, configPath?: string, cwd?: string): string {
  const external = process.env.PALIZADE_SEAL_PATH;
  if (external === undefined) {
    const legacy = join(config.stateDir, "seal.json");
    if (!configPath) return legacy;
    const anchored = defaultSealPath(configPath);
    return anchored !== legacy && !sealEntryExists(anchored) && sealEntryExists(legacy) ? legacy : anchored;
  }
  if (!isAbsolute(external)) throw new Error("PALIZADE_SEAL_PATH must be an absolute path.");
  const configDir = configPath ? dirname(resolve(configPath)) : undefined;
  const launcher = process.cwd();
  const workspace = cwd ?? (configDir && relative(launcher, homedir()) === "" ? configDir : launcher);
  const checkpoint = resolveArgumentPath(external, workspace);
  if (checkpoint.uncertain) throw new Error("PALIZADE_SEAL_PATH could not be safely canonicalized.");
  const path = join(realpathSync.native(dirname(external)), basename(external));
  const roots: [string, string][] = [
    [config.stateDir, "stateDir"], [workspace, "the workspace working directory"]
  ];
  if (configDir) roots.unshift([configDir, "the directory containing palizade.yaml"]);
  for (const [root, name] of roots) {
    const directory = resolveArgumentPath(root, workspace);
    if (directory.uncertain || isInside(directory.logical, checkpoint.logical) || isInside(directory.canonical, checkpoint.canonical)) {
      throw new Error(`PALIZADE_SEAL_PATH must be outside ${name}.`);
    }
  }
  const entry = lstatSync(path, { throwIfNoEntry: false });
  if (entry && !entry.isFile()) throw new Error("PALIZADE_SEAL_PATH must name a regular file.");
  return checkpoint.canonical;
}

function isInside(directory: string, path: string): boolean {
  const delta = relative(directory, path);
  return !isAbsolute(delta) && delta !== ".." && !delta.startsWith(`..${sep}`);
}

function sealEntryExists(path: string): boolean {
  return lstatSync(path, { throwIfNoEntry: false }) !== undefined;
}

export function sealEnabled(config: SealConfig, configPath?: string, cwd?: string): boolean {
  const path = sealPath(config, configPath, cwd);
  return process.env.PALIZADE_SEAL_PATH !== undefined || sealEntryExists(path);
}

function readSealFile(path: string): Buffer | null {
  try {
    return readFileSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !sealEntryExists(path)) return null;
    throw error;
  }
}

function sealHash(bytes: Buffer | null): string {
  return bytes === null ? "missing" : createHash("sha256").update(bytes).digest("hex");
}

export function readSealSidecars(config: Pick<PalizadeConfig, "egress" | "lockfile">) {
  const learnedBytes = readSealFile(config.egress.learnedFile);
  const lockBytes = readSealFile(config.lockfile);
  const hashes = { [resolve(config.egress.learnedFile)]: sealHash(learnedBytes), [resolve(config.lockfile)]: sealHash(lockBytes) };
  return { learnedBytes, lockBytes, hashes };
}

export function sealFiles(config: SealConfig, required: readonly string[]): string[] {
  const files = [...required];
  if (config.egress) files.push(config.egress.learnedFile);
  if (config.lockfile) files.push(config.lockfile);
  return [...new Set(files.map((file) => resolve(file)))];
}

export function writeSeal(config: SealConfig, files: readonly string[]): Record<string, string> {
  const path = process.env.PALIZADE_SEAL_PATH === undefined && files[0] ? defaultSealPath(files[0]) : sealPath(config, files[0]);
  const allFiles = sealFiles(config, files);
  const checkpoint = resolveArgumentPath(path, process.cwd()).canonical;
  if (allFiles.some((file) => relative(path, file) === "" || (existsSync(file) && relative(checkpoint, realpathSync(file)) === ""))) {
    throw new Error("The seal file must be separate from the files it covers.");
  }
  const seal = Object.fromEntries(allFiles.map((file) => [file, sealHash(readSealFile(file))]));
  if (files.some((file) => seal[resolve(file)] === "missing")) throw new Error("Cannot seal a missing configuration or policy file.");
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(seal, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
  return seal;
}

/** Check the current files and, when supplied, the exact bytes already loaded by the runtime. */
export function sealDrift(
  config: SealConfig,
  files?: readonly string[],
  loaded?: Readonly<Record<string, string>>,
  required = false,
  cwd?: string
): string[] {
  const path = sealPath(config, files?.[0], cwd);
  const external = process.env.PALIZADE_SEAL_PATH !== undefined;
  try {
    const seal: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!seal || typeof seal !== "object" || Array.isArray(seal)) return [path];
    const entries = Object.entries(seal);
    const mandatory = files?.map((file) => resolve(file));
    if (entries.length === 0 || entries.some(([file, hash]) => !isAbsolute(file) || typeof hash !== "string" ||
        (hash === "missing" ? mandatory?.includes(file) : !/^[a-f0-9]{64}$/u.test(hash)))) return [path];
    if (external && !files) return [path];
    const expected = sealFiles(config, files ?? []);
    const absent = expected.filter((file) => !Object.hasOwn(seal, file));
    const changed = entries.filter(([file, hash]) => sealHash(readSealFile(file)) !== hash ||
      (loaded && expected.includes(file) && loaded[file] !== hash)).map(([file]) => file);
    return [...absent, ...changed];
  } catch (error) {
    if (!required && !external && (error as NodeJS.ErrnoException).code === "ENOENT" && !sealEntryExists(path)) return [];
    return [path];
  }
}
