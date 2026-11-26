import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { afterEach, expect, it, vi } from "vitest";
import { launchUpstream } from "./launch.js";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));
vi.mock("node:fs", async (importOriginal) => ({ ...await importOriginal<typeof import("node:fs")>(), existsSync: vi.fn() }));

afterEach(() => vi.resetAllMocks());

it.runIf(process.platform === "win32")("does not rewrite an unresolved npx.cmd from the working directory", async () => {
  vi.mocked(existsSync).mockReturnValue(true);
  vi.mocked(spawn).mockImplementation(() => {
    const child = new EventEmitter();
    queueMicrotask(() => child.emit("spawn"));
    return child as ReturnType<typeof spawn>;
  });
  await launchUpstream("npx", { command: "npx.cmd", args: ["--version"], cwd: process.cwd(), env: {} }, { resolveCommand: (command) => command });
  expect(existsSync).not.toHaveBeenCalled();
  expect(spawn).toHaveBeenCalledWith("npx.cmd", ["--version"], expect.objectContaining({ shell: false }));
});
