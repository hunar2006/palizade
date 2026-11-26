import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

const windows = process.platform === "win32";
const venv = join(import.meta.dirname, "..", ".venv");
const python = join(venv, windows ? "Scripts/python.exe" : "bin/python");

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) console.error(result.error.message);
  if (result.status !== 0) process.exit(result.status ?? 1);
}

switch (process.argv[2]) {
  case "setup":
    if (!existsSync(python)) {
      run(windows ? "python" : "python3", ["-I", "-m", "venv", venv]);
    }
    run(python, ["-I", "-m", "pip", "--disable-pip-version-check", "install", "agentdojo==0.1.35"]);
    console.log("AgentDojo 0.1.35 environment ready.");
    break;
  case "smoke":
    run(python, ["-E", "-B", "-X", "utf8", join(import.meta.dirname, "smoke.py")]);
    break;
  case "live":
    run(python, ["-E", "-B", "-X", "utf8", join(import.meta.dirname, "run_live.py"), ...process.argv.slice(3)]);
    break;
  default:
    throw new Error("Expected setup, smoke, or live.");
}
