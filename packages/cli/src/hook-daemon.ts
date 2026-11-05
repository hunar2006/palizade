// `palizade daemon`: answers hook calls for one config file over a Unix socket (macOS, Linux) or a
// named pipe (Windows), so each hook call skips loading Palizade and parsing its config.
import { randomBytes } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer, type Server } from "node:net";
import { DAEMON_MAX_INPUT_BYTES, DAEMON_PROTOCOL, daemonEndpoint, daemonRunDir, sign, signatureMatches, type HookArgs, type HookRun } from "./hook-client.js";

export type HookHandler = (args: HookArgs, cwd: string, stdin: Buffer) => Promise<HookRun>;

export interface HookDaemon { socket: string; close(): Promise<void> }

function privateRunDir(): string {
  const dir = daemonRunDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") {
    const info = lstatSync(dir);
    // Another user who could write here could replace the socket or read the key.
    if (!info.isDirectory() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) {
      throw new Error(`${dir} must be a directory owned by you with mode 700.`);
    }
  }
  return dir;
}

function inUse(socket: string): Promise<boolean> {
  return new Promise((resolveInUse) => {
    const probe = connect(socket);
    probe.on("connect", () => { probe.destroy(); resolveInUse(true); });
    probe.on("error", () => resolveInUse(false));
  });
}

export async function startHookDaemon(configPath: string, handle: HookHandler): Promise<HookDaemon> {
  privateRunDir();
  const { socket, keyFile } = daemonEndpoint(configPath);
  if (await inUse(socket)) throw new Error(`A daemon for ${configPath} is already running (${socket}).`);
  if (process.platform !== "win32") rmSync(socket, { force: true });
  const key = randomBytes(32);
  const temporary = `${keyFile}.${process.pid}.tmp`;
  writeFileSync(temporary, key.toString("hex"), { mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, keyFile);

  // One call at a time, like hooks that each wait for the client's previous tool call.
  let queue: Promise<unknown> = Promise.resolve();
  const answer = async (line: string): Promise<string | undefined> => {
    const request = JSON.parse(line) as { body?: unknown; mac?: unknown };
    if (typeof request.body !== "string" || !signatureMatches(key, request.body, request.mac)) return undefined;
    const body = JSON.parse(request.body) as { v?: unknown; nonce?: unknown; config?: unknown; args?: HookArgs; cwd?: unknown; runId?: unknown; stdin?: unknown };
    if (typeof body.nonce !== "string") return undefined;
    const reply = (value: object) => { const text = JSON.stringify(value); return JSON.stringify({ body: text, mac: sign(key, `${body.nonce}\n${text}`) }); };
    // Anything this daemon would answer differently from an in process run goes back to the client.
    if (body.v !== DAEMON_PROTOCOL || body.config !== configPath || (body.runId ?? null) !== (process.env.PALIZADE_RUN_ID ?? null)
      || typeof body.cwd !== "string" || typeof body.stdin !== "string" || !body.args) return reply({ fallback: true });
    const run = queue.then(() => handle(body.args!, body.cwd as string, Buffer.from(body.stdin as string, "base64")));
    queue = run.catch(() => undefined);
    try { return reply(await run); } catch { return reply({ fallback: true }); }
  };

  const server: Server = createServer((connection) => {
    let data = "";
    connection.setEncoding("utf8");
    connection.on("error", () => connection.destroy());
    connection.on("data", (chunk: string) => {
      data += chunk;
      if (data.length > 2 * DAEMON_MAX_INPUT_BYTES) { connection.destroy(); return; }
      const end = data.indexOf("\n");
      if (end < 0) return;
      connection.removeAllListeners("data");
      answer(data.slice(0, end)).then((text) => { if (text) connection.end(`${text}\n`); else connection.destroy(); }, () => connection.destroy());
    });
  });
  await new Promise<void>((resolveListen, reject) => { server.once("error", reject); server.listen(socket, () => resolveListen()); });
  if (process.platform !== "win32") chmodSync(socket, 0o600);

  return {
    socket,
    close: async () => {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      rmSync(keyFile, { force: true });
      if (process.platform !== "win32") rmSync(socket, { force: true });
    }
  };
}
