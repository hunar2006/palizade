// Thin client for `palizade hook`: hands the call to a running `palizade daemon` before the main
// bundle loads. Only node built ins, so the launcher can load it in a few milliseconds. Any
// failure returns false and the caller runs the hook in process, exactly as without a daemon.
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export const DAEMON_PROTOCOL = 1;
/** Larger inputs skip the daemon; the in process path then applies hooks.maxInputBytes as before. */
export const DAEMON_MAX_INPUT_BYTES = 8 * 1024 * 1024;
const CLIENT_TIMEOUT_MS = 10_000;

export interface HookArgs { config: string; client?: string; event?: string; session?: string; cwd?: string }
export interface HookRun { stdout: string; stderr: string; exitCode: number }
/** Stdin the client already read, for the in process fallback. */
export interface PreloadedStdin { chunks: Buffer[]; ended: boolean }

export function daemonRunDir(): string {
  return join(homedir(), ".palizade", "run");
}

/** One daemon per config file, keyed by its absolute path. */
export function daemonEndpoint(configPath: string): { socket: string; keyFile: string } {
  const id = createHash("sha256").update(resolve(configPath)).digest("hex").slice(0, 16);
  const socket = process.platform === "win32" ? `\\\\.\\pipe\\palizade-${id}` : join(daemonRunDir(), `${id}.sock`);
  return { socket, keyFile: join(daemonRunDir(), `${id}.key`) };
}

export function sign(key: Buffer, text: string): string {
  return createHmac("sha256", key).update(text).digest("hex");
}

export function signatureMatches(key: Buffer, text: string, signature: unknown): boolean {
  if (typeof signature !== "string" || !/^[0-9a-f]{64}$/u.test(signature)) return false;
  return timingSafeEqual(Buffer.from(sign(key, text), "hex"), Buffer.from(signature, "hex"));
}

/**
 * Parses `[-c file] hook <client> [event] [--session id] [--cwd dir]` the way commander does for
 * the hook command. Returns undefined for anything else, which then never uses the daemon.
 */
export function parseHookArgs(argv: string[]): HookArgs | undefined {
  let config = "palizade.yaml";
  let index = 0;
  for (; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === "-c" || arg === "--config") { const value = argv[++index]; if (value === undefined) return undefined; config = value; continue; }
    if (arg.startsWith("--config=")) { config = arg.slice("--config=".length); continue; }
    break;
  }
  if (argv[index] !== "hook") return undefined;
  const result: HookArgs = { config };
  const positionals: string[] = [];
  for (index += 1; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === "--session" || arg === "--cwd") {
      const value = argv[++index];
      if (value === undefined) return undefined;
      result[arg === "--session" ? "session" : "cwd"] = value;
    } else if (arg.startsWith("--session=")) result.session = arg.slice("--session=".length);
    else if (arg.startsWith("--cwd=")) result.cwd = arg.slice("--cwd=".length);
    else if (arg.startsWith("-")) return undefined; // an option this parser does not know: let commander handle it
    else positionals.push(arg);
  }
  if (positionals.length < 1 || positionals.length > 2 || !config) return undefined;
  result.client = positionals[0]!;
  if (positionals[1] !== undefined) result.event = positionals[1];
  return result;
}

async function readInput(preloaded: PreloadedStdin): Promise<boolean> {
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    preloaded.chunks.push(buffer);
    total += buffer.length;
    if (total > DAEMON_MAX_INPUT_BYTES) return false;
  }
  preloaded.ended = true;
  return true;
}

function exchange(socket: string, line: string): Promise<string> {
  return new Promise((resolveLine, reject) => {
    const connection = connect(socket);
    let data = "";
    const timer = setTimeout(() => { connection.destroy(); reject(new Error("daemon timeout")); }, CLIENT_TIMEOUT_MS);
    connection.setEncoding("utf8");
    connection.on("connect", () => connection.write(line));
    connection.on("data", (chunk: string) => {
      data += chunk;
      const end = data.indexOf("\n");
      if (end >= 0) { clearTimeout(timer); connection.end(); resolveLine(data.slice(0, end)); }
      else if (data.length > 4 * DAEMON_MAX_INPUT_BYTES) { clearTimeout(timer); connection.destroy(); reject(new Error("daemon reply too large")); }
    });
    connection.on("error", (error) => { clearTimeout(timer); reject(error); });
    connection.on("close", () => { clearTimeout(timer); reject(new Error("daemon closed")); });
  });
}

/** Returns true when the daemon answered and its output was written; false means run in process. */
export async function tryDaemon(argv: string[], preloaded: PreloadedStdin): Promise<boolean> {
  if (process.env.PALIZADE_NO_DAEMON) return false;
  const args = parseHookArgs(argv);
  if (!args) return false;
  const config = resolve(args.config);
  const { socket, keyFile } = daemonEndpoint(config);
  let key: Buffer;
  try { key = Buffer.from(readFileSync(keyFile, "utf8").trim(), "hex"); } catch { return false; }
  if (key.length !== 32) return false;
  try {
    if (!await readInput(preloaded)) return false;
    const nonce = randomBytes(16).toString("hex");
    const body = JSON.stringify({ v: DAEMON_PROTOCOL, nonce, config, args, cwd: process.cwd(), runId: process.env.PALIZADE_RUN_ID ?? null, stdin: Buffer.concat(preloaded.chunks).toString("base64") });
    const reply = JSON.parse(await exchange(socket, `${JSON.stringify({ body, mac: sign(key, body) })}\n`)) as { body?: unknown; mac?: unknown };
    if (typeof reply.body !== "string" || !signatureMatches(key, `${nonce}\n${reply.body}`, reply.mac)) return false;
    const run = JSON.parse(reply.body) as Partial<HookRun> & { fallback?: boolean };
    if (run.fallback || typeof run.stdout !== "string" || typeof run.stderr !== "string" || !Number.isInteger(run.exitCode)) return false;
    if (run.stdout) process.stdout.write(run.stdout);
    if (run.stderr) process.stderr.write(run.stderr);
    process.exitCode = run.exitCode!;
    return true;
  } catch {
    return false;
  }
}
