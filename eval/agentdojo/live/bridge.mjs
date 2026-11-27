import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rmdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { AuditLogger } from "../../../packages/audit/dist/index.js";
import { createDetector, InterceptionEngine, LockfileStore, parseConfig } from "../../../packages/core/dist/index.js";
import { parsePolicy } from "../../../packages/policy/dist/index.js";
import { extractStatedObservables, InMemoryTaintStore } from "../../../packages/taint/dist/index.js";
import { benchmarkTempBase } from "./temp-base.mjs";

const root = resolve(import.meta.dirname, "../../..");

class ProtocolError extends Error {}

class EpisodeLock extends LockfileStore {
  constructor(path, suite) {
    super(path);
    this.lock = { version: 1, servers: { [suite]: { tools: Object.create(null) } } };
  }

  async read() {
    return this.lock;
  }

  async write(lock) {
    this.lock = lock;
  }
}

function requireInput(condition, message) {
  if (!condition) throw new ProtocolError(message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function decisionDetails(event, fallback) {
  return { ruleId: event?.matched_rule?.id ?? null, reason: event?.reason ?? fallback };
}

function decisionEvent(state, direction, method) {
  return state.events.findLast((event) => event.direction === direction && event.method === method);
}

async function start({ suite, tools, prompt, preset, approvals = "deny" }, presets, stateDir) {
  requireInput(typeof suite === "string" && /^[a-z][a-z0-9_-]*$/u.test(suite), "Invalid suite name.");
  requireInput(presets.has(preset), "Expected the default or strict preset.");
  requireInput(approvals === "deny" || approvals === "approve", "Expected approvals to be deny or approve.");
  requireInput(typeof prompt === "string", "Expected a user prompt string.");
  requireInput(Array.isArray(tools) && tools.every((tool) => isObject(tool) &&
    typeof tool.name === "string" && tool.name.length > 0 &&
    (tool.description === undefined || typeof tool.description === "string") && isObject(tool.inputSchema)),
  "Expected tool schemas with name, optional description, and inputSchema.");
  requireInput(new Set(tools.map(({ name }) => name)).size === tools.length, "Duplicate tool names.");

  const config = parseConfig(JSON.stringify({
    stateDir,
    policy: "unused",
    lockfile: join(stateDir, "palizade.lock"),
    servers: { [suite]: { command: "agentdojo", trust: "untrusted" } }
  }), stateDir);
  const lockfile = new EpisodeLock(config.lockfile, suite);
  await lockfile.approveTools(suite, tools);
  const state = { approvalPrompts: 0, approvalDenials: 0, events: [], pending: undefined };
  const taintStore = new InMemoryTaintStore();
  const sessionId = randomUUID();
  taintStore.addUserStatements(sessionId, extractStatedObservables(prompt), 3_600_000);
  state.engine = new InterceptionEngine({
    config,
    serverName: suite,
    server: config.servers[suite],
    sessionId,
    policy: presets.get(preset),
    detector: createDetector(config),
    taintStore,
    audit: new AuditLogger([{ write: async (event) => { state.events.push(event); } }]),
    approvals: { requestApproval: async (request) => {
      state.approvalPrompts++;
      if (preset === "strict" && request.method === "tools/list" && request.tool === undefined &&
          request.reason === "policy default" && request.details?.matchedRuleId === undefined) {
        return { approved: true, reason: "The benchmark runner approved the supplied catalog", approver: "agentdojo" };
      }
      if (approvals === "approve") {
        return { approved: true, reason: "Episode approvals are granted", approver: "agentdojo" };
      }
      state.approvalDenials++;
      return { approved: false, reason: "Other episode approvals are denied", approver: "agentdojo" };
    } },
    lockfile
  });

  await state.engine.handleClientMessage({ jsonrpc: "2.0", id: 0, method: "tools/list", params: {} });
  const listing = await state.engine.handleServerMessage({ jsonrpc: "2.0", id: 0, result: { tools } });
  state.available = new Set((listing.toClient[0]?.result?.tools ?? []).map(({ name }) => name));
  state.listDecision = decisionDetails(decisionEvent(state, "response", "tools/list"), "Tool catalog withheld by policy.");
  return state;
}

export async function serve(presets) {
  const stateDir = await mkdtemp(join(await benchmarkTempBase(), "palizade-agentdojo-bridge-"));
  let episode;
  let nextCallId = 1;

  async function handle(message) {
    requireInput(isObject(message), "Expected a request object.");
    if (message.op === "start") {
      requireInput(!episode, "End the active episode before starting another.");
      episode = await start(message, presets, stateDir);
      return { availableTools: [...episode.available] };
    }
    requireInput(episode, "Start an episode first.");

    switch (message.op) {
      case "check": {
        requireInput(episode.pending === undefined, "Record the previous tool result first.");
        requireInput(typeof message.name === "string" && isObject(message.arguments), "Invalid tool call.");
        if (!episode.available.has(message.name)) {
          return {
            decision: "block",
            ...(episode.available.size ? { ruleId: null, reason: "Tool is unavailable in this episode." } : episode.listDecision)
          };
        }

        episode.events.length = 0;
        const approvalsBefore = episode.approvalPrompts;
        const denialsBefore = episode.approvalDenials;
        const callId = nextCallId++;
        const request = await episode.engine.handleClientMessage({
          jsonrpc: "2.0", id: callId, method: "tools/call",
          params: { name: message.name, arguments: message.arguments }
        });
        const event = decisionEvent(episode, "request", "tools/call");
        const approvalPrompted = episode.approvalPrompts > approvalsBefore;
        const approvalDenied = episode.approvalDenials > denialsBefore;
        const forwarded = request.toServer[0];
        if (!forwarded) {
          return { decision: approvalDenied ? "needs_approval" : "block", approvalPrompted, ...decisionDetails(event, "Tool call blocked by policy.") };
        }
        episode.pending = callId;
        return {
          decision: "allow", approvalPrompted, ...decisionDetails(event, "Tool call allowed."),
          callId, arguments: forwarded.params.arguments
        };
      }
      case "record": {
        requireInput(episode.pending !== undefined && message.callId === episode.pending, "No matching allowed tool call.");
        requireInput(typeof message.result === "string" && typeof message.isError === "boolean", "Invalid tool result.");
        episode.events.length = 0;
        const response = await episode.engine.handleServerMessage({
          jsonrpc: "2.0", id: message.callId,
          result: { content: [{ type: "text", text: message.result }], isError: message.isError }
        });
        episode.pending = undefined;
        const content = response.toClient[0]?.result?.content;
        const singleTextBlock = Array.isArray(content) && content.length === 1 && content[0]?.type === "text" && typeof content[0].text === "string";
        const result = singleTextBlock ? content[0].text : null;
        return {
          result, blocked: result === null,
          ...decisionDetails(decisionEvent(episode, "response", "tools/call"), result === null ? "Tool result blocked by policy." : "Tool result allowed.")
        };
      }
      case "end": {
        const { approvalPrompts } = episode;
        episode = undefined;
        return { approvalPrompts };
      }
      default:
        throw new ProtocolError("Unknown operation.");
    }
  }

  try {
    for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
      let reply;
      try {
        reply = { ok: true, ...await handle(JSON.parse(line)) };
      } catch (error) {
        const message = error instanceof ProtocolError ? error.message :
          error instanceof SyntaxError ? "Malformed JSON." : "Bridge could not process the request.";
        reply = { ok: false, error: message };
      }
      process.stdout.write(`${JSON.stringify(reply)}\n`);
    }
  } finally {
    await rmdir(stateDir);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const presets = new Map(await Promise.all(["default", "strict"].map(async (preset) => [
    preset, parsePolicy(await readFile(join(root, "policies", `${preset}.yaml`), "utf8"))
  ])));
  await serve(presets);
}
