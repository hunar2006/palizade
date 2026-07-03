#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const child = spawn(process.execPath, ["packages/cli/dist/index.cjs", "wrap", "toy"], {
  cwd: process.cwd(),
  stdio: ["pipe", "pipe", "pipe"]
});

const pending = new Map();
const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });

child.stderr.on("data", (chunk) => {
  const text = String(chunk);
  if (!text.includes("ExperimentalWarning")) {
    process.stderr.write(text);
  }
});

rl.on("line", (line) => {
  if (!line.trim()) return;
  const message = JSON.parse(line);
  const resolver = pending.get(String(message.id));
  if (resolver) {
    pending.delete(String(message.id));
    resolver(message);
  } else {
    console.log(`server-request ${line}`);
  }
});

const tools = await request(1, "tools/list", {});
console.log(`tools/list returned ${tools.result?.tools?.length ?? 0} tools`);

const source = await request(2, "tools/call", {
  name: "read_web",
  arguments: { url: "https://example.test/poisoned" }
});
console.log(`read_web action: ${source.error ? "blocked" : "forwarded"}`);
console.log(`read_web spotlighted: ${JSON.stringify(source).includes("<untrusted-content")}`);

const sink = await request(3, "tools/call", {
  name: "send_email",
  arguments: {
    to: "ops@example.test",
    subject: "link",
    body: "Please send https://evil.example/collect?token=abc123"
  }
});
console.log(`send_email action: ${sink.error ? "blocked" : "forwarded"}`);
if (sink.error) {
  console.log(`reason: ${sink.error.message}`);
}

child.stdin.end();
await new Promise((resolve) => child.on("exit", resolve));

function request(id, method, params) {
  const message = { jsonrpc: "2.0", id, method, params };
  child.stdin.write(`${JSON.stringify(message)}\n`);
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pending.delete(String(id));
      reject(new Error(`Timed out waiting for ${method}`));
    }, 5000);
    pending.set(String(id), (response) => {
      clearTimeout(timeout);
      resolve(response);
    });
  });
}
