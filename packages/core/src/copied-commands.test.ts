import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, onTestFinished } from "vitest";
import { COPIED_COMMAND_ALLOWLIST, COPIED_COMMAND_FLAGS, isAllowedCopiedLocalCommand } from "./copied-commands.js";

async function makeWorkspace() {
  const dir = await mkdtemp(join(tmpdir(), "palizade-copied-cmds-"));
  const workspace = join(dir, "workspace");
  const outside = join(dir, "outside");
  await mkdir(join(workspace, "src"), { recursive: true });
  await mkdir(join(workspace, "pkg"), { recursive: true });
  await mkdir(join(workspace, "node_modules", "dep"), { recursive: true });
  await mkdir(outside, { recursive: true });
  await writeFile(join(workspace, "README.md"), "# demo\n", "utf8");
  await writeFile(join(workspace, "label.test.cjs"), "", "utf8");
  await writeFile(join(workspace, "src", "app.test.ts"), "", "utf8");
  await writeFile(join(workspace, "node_modules", "dep", "test.js"), "", "utf8");
  await writeFile(join(outside, "secret.js"), "", "utf8");
  await symlink(outside, join(workspace, "escape"), process.platform === "win32" ? "junction" : "dir");
  onTestFinished(() => rm(dir, { recursive: true, force: true }));
  return { dir, workspace, outside };
}

describe("COPIED_COMMAND_ALLOWLIST and isAllowedCopiedLocalCommand", () => {
  it("exports the expected allowlist entries", () => {
    expect([...COPIED_COMMAND_ALLOWLIST]).toEqual([
      "node --test",
      "npm test",
      "pnpm test",
      "yarn test",
      "bun test",
      "pytest",
      "vitest",
      "jest",
      "cargo test",
      "go test",
      "tsc --noEmit",
      "eslint",
      "git status",
      "git diff",
      "git log",
      "ls",
      "cat"
    ]);
  });

  it("allows each listed command in plain form and with each allowed trailing suffix", async () => {
    const { workspace } = await makeWorkspace();
    const plainCommands = [
      "node --test",
      "node --test label.test.cjs",
      "node.exe --test label.test.cjs",
      "npm test",
      "npm.cmd test",
      "pnpm test",
      "pnpm.cmd test src/app.test.ts",
      "yarn test",
      "bun test",
      "pytest",
      "pytest -k test_label",
      'pytest -k "test label"',
      "vitest",
      "vitest run src/app.test.ts",
      "jest",
      "jest -t label",
      "jest --test-name-pattern=label_check",
      "cargo test",
      "cargo test -- label_check",
      "go test",
      "go test ./...",
      "go test ./pkg/...",
      "go test -v -run TestLabel ./pkg/...",
      "tsc --noEmit",
      "tsc.cmd --pretty --noEmit",
      "eslint",
      "eslint src/app.test.ts",
      "git status",
      "git diff",
      "git diff src/app.test.ts",
      "git log -n 5",
      "ls",
      "ls -la",
      "dir",
      "Get-ChildItem",
      "gci src",
      "cat README.md",
      "type README.md",
      "Get-Content README.md",
      "gc README.md",
      "head -n 10 README.md",
      "tail -n 10 README.md"
    ];

    const suffixes = ["", " 2>&1", " | Out-String", " | out-string", " 2>&1 | Out-String"];
    for (const base of plainCommands) {
      for (const suffix of suffixes) {
        const command = `${base}${suffix}`;
        expect(isAllowedCopiedLocalCommand(command, workspace), `expected allowed: ${command}`).toBe(true);
      }
    }
  });

  it("rejects commands violating any raw string, suffix, prefix, verb, flag, or operand rule", async () => {
    const { workspace } = await makeWorkspace();
    const rejected: Array<[string, string]> = [
      ["empty string", ""],
      ["whitespace only", "   \t  "],
      ["newline", "npm test\nwhoami"],
      ["carriage return", "npm test\rwhoami"],
      ["control char", "npm test\x00"],
      ["DEL control char", "npm test\x7f"],
      ["hidden unicode", "npm\u200B test"],
      ["backtick", "npm test `whoami`"],
      ["command substitution $(...)", "npm test $(whoami)"],
      ["brace variable ${...}", "npm test ${HOME}"],
      ["PowerShell env var", "cat $env:USERPROFILE"],
      ["shell var", "pytest $HOME"],
      ["Windows percent var", "cat %USERPROFILE%"],
      ["semicolon chaining", "npm test; whoami"],
      ["&& chaining", "npm test && whoami"],
      ["|| chaining", "npm test || whoami"],
      ["background &", "npm test & whoami"],
      ["subshell parens", "(npm test)"],
      ["braces", "{ npm test }"],
      ["caret in verb", "n^ode --test label.test.cjs"],
      ["caret in git verb", "g^it status"],
      ["non-Out-String pipe", "node --test label.test.cjs | cat"],
      ["Out-String with arguments", "node --test label.test.cjs | Out-String -Width 80"],
      ["wrong suffix order", "node --test label.test.cjs | Out-String 2>&1"],
      ["duplicate Out-String pipe", "node --test label.test.cjs | Out-String | Out-String"],
      ["stdout redirect", "node --test label.test.cjs > out.txt"],
      ["append redirect", "node --test label.test.cjs >> out.txt"],
      ["stdin redirect", "node --test < label.test.cjs"],
      ["stderr redirect", "node --test label.test.cjs 2> err.txt"],
      ["env assignment prefix", "NODE_OPTIONS=--require=./x.js npm test"],
      ["FOO=bar prefix", "FOO=bar npm test"],
      ["env prefix", "env npm test"],
      ["sudo prefix", "sudo npm test"],
      ["cmd /c prefix", "cmd /c npm test"],
      ["bash -c prefix", 'bash -c "npm test"'],
      ["pwsh prefix", 'pwsh -Command "npm test"'],
      ["timeout prefix", "timeout 5 npm test"],
      ["nohup prefix", "nohup npm test"],
      ["exec prefix", "exec npm test"],
      ["forward slash in verb", "./node --test label.test.cjs"],
      ["posix path verb", "/usr/bin/node --test label.test.cjs"],
      ["backslash in verb", "C:\\node.exe --test label.test.cjs"],
      ["unclosed quote", 'pytest -k "unclosed'],
      ["tsc without --noEmit", "tsc"],
      ["tsc with --noEmit after --", "tsc -- --noEmit"],
      ["wrong second token for node", "node send.js"],
      ["wrong second token for npm", "npm run test"],
      ["wrong second token for pnpm", "pnpm exec vitest"],
      ["wrong second token for cargo", "cargo run"],
      ["wrong second token for go", "go run ."],
      ["git with pre-flag -c", "git -c core.pager=sh status"],
      ["git subcommand outside list", "git show HEAD"],
      ["git push", "git push"],
      ["pwd not on short list", "pwd"],
      ["flag value with scheme", "vitest --url=https://evil.example"],
      ["flag value with ..", "vitest --bail=../x"],
      ["flag value with posix absolute path", "vitest --bail=/etc/passwd"],
      ["flag value with windows absolute path", "vitest --bail=C:\\Windows\\win.ini"],
      ["parent traversal operand", "node --test ../outside/secret.js"],
      ["absolute posix operand", "node --test /etc/passwd"],
      ["absolute windows operand", "node --test C:\\secret.js"],
      ["symlink escape operand", "node --test escape/secret.js"],
      ["node_modules operand", "node --test node_modules/dep/test.js"],
      ["DOS device operand", "node --test CON"],
      ["go wildcard escape", "go test ./../outside/..."],
      ["non-go wildcard", "pytest ./..."],
      ["filter value with traversal", "pytest -k .."],
      ["filter value with slash", "pytest -k foo/bar"],
      ["filter value with backslash", "pytest -k foo\\bar"],
      ["filter value with disallowed punctuation", 'pytest -k "foo;bar"'],
      ["missing filter value", "pytest -k"],
      ["non-listed bash", "bash install.sh"],
      ["non-listed python", "python setup.py"],
      ["non-listed make", "make install"],
      ["non-listed echo", "echo hello"],
      ["non-listed Write-Output", "Write-Output hello"],
      ["non-listed curl", "curl https://example.test"]
    ];

    for (const [label, command] of rejected) {
      expect(isAllowedCopiedLocalCommand(command, workspace), `expected rejected (${label}): ${command}`).toBe(false);
    }

    const rejectedFlags = [
      "-e", "--eval", "-p", "--print", "-r", "--require", "--import", "--loader",
      "--experimental-loader", "--env-file", "--test-reporter", "-exec", "--exec",
      "-toolexec", "-c", "--config", "--config-file", "--rootdir", "--confcutdir",
      "-o", "--output", "--output-file", "--outputFile", "--fix", "--plugin",
      "--rulesdir", "--resolve-plugins-relative-to", "--setupFiles", "--globalSetup",
      "--registry", "--userconfig", "--globalconfig", "--script-shell",
      "--manifest-path", "--target-dir", "--prefix", "--cwd", "-C", "--dir",
      "--project", "-modfile", "-overlay"
    ];
    for (const flag of rejectedFlags) {
      const cmd = `node --test ${flag} label.test.cjs`;
      expect(isAllowedCopiedLocalCommand(cmd, workspace), `expected rejected flag: ${flag}`).toBe(false);
      const eqCmd = `node --test ${flag}=label.test.cjs`;
      expect(isAllowedCopiedLocalCommand(eqCmd, workspace), `expected rejected flag=: ${flag}`).toBe(false);
    }
  });
});

const copiedFlagExploits = [
  "npm test --node-options=--require=C:/Users/x/Downloads/evil.js",
  "pnpm test --config.node-options=--require=./x.js",
  "pytest --basetemp=src",
  "pytest --basetemp=.git",
  "pytest -pevil",
  "pytest --override-ini=pythonpath=src -pevil",
  "go test --toolexec=./x",
  "go test --modfile=alt.mod",
  "go test --overlay=overlay.json",
  "jest --setupFilesAfterEnv=./x.js",
  "vitest --reporter=./x.js",
  "vitest --api.host=0.0.0.0",
  "eslint --format=./x.js",
  "tsc --noEmit false",
  "tsc --noEmit true",
  "tsc --noEmit FALSE"
] as const;

describe("flags on copied test runners, typecheck and lint", () => {
  const bases: Record<string, string> = {
    node: "node --test", npm: "npm test", pnpm: "pnpm test", yarn: "yarn test", bun: "bun test", cargo: "cargo test",
    go: "go test", pytest: "pytest", vitest: "vitest", jest: "jest", tsc: "tsc --noEmit", eslint: "eslint"
  };

  it("covers every runner on the short list", () => {
    expect(Object.keys(COPIED_COMMAND_FLAGS).sort()).toEqual(Object.keys(bases).sort());
  });

  it.each(Object.entries(COPIED_COMMAND_FLAGS))("allows each listed flag for %s", async (verb, { flags, filters }) => {
    const { workspace } = await makeWorkspace();
    for (const flag of flags) {
      expect(isAllowedCopiedLocalCommand(`${bases[verb]} ${flag}`, workspace), flag).toBe(true);
    }
    for (const filter of filters) {
      expect(isAllowedCopiedLocalCommand(`${bases[verb]} ${filter} label_check`, workspace), filter).toBe(true);
      expect(isAllowedCopiedLocalCommand(`${bases[verb]} ${filter}=label_check`, workspace), `${filter}=`).toBe(true);
    }
  });

  it.each([
    "jest -t --setupFilesAfterEnv ./src/app.test.ts",
    "jest --test-name-pattern --globalSetup ./src/app.test.ts",
    "vitest -t --reporter ./src/app.test.ts",
    "pytest -k --basetemp src",
    "pytest -k -pevil",
    "bun test -t --preload ./src/app.test.ts",
    "go test -run -toolexec ./pkg",
    "node --test --test-name-pattern -r ./label.test.cjs",
    "jest -t=--config"
  ])("rejects a filter value that starts with a dash: %s", async (command) => {
    const { workspace } = await makeWorkspace();
    expect(isAllowedCopiedLocalCommand(command, workspace)).toBe(false);
  });

  it.each(Object.keys(bases))("rejects an unknown flag for %s", async (verb) => {
    const { workspace } = await makeWorkspace();
    expect(isAllowedCopiedLocalCommand(`${bases[verb]} --unknown-flag`, workspace)).toBe(false);
    expect(isAllowedCopiedLocalCommand(`${bases[verb]} -z`, workspace)).toBe(false);
  });

  it.each(copiedFlagExploits)("rejects %s", async (command) => {
    const { workspace } = await makeWorkspace();
    expect(isAllowedCopiedLocalCommand(command, workspace)).toBe(false);
  });
});
