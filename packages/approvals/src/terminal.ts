import { randomUUID } from "node:crypto";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import type { ApprovalDecision, ApprovalDefault, ApprovalProvider, ApprovalRequest } from "./types.js";

export interface TerminalApprovalOptions {
  defaultDecision: ApprovalDefault;
}

export class TerminalApprovalProvider implements ApprovalProvider {
  constructor(private readonly options: TerminalApprovalOptions = { defaultDecision: "deny" }) {}

  async requestApproval(request: ApprovalRequest): Promise<ApprovalDecision> {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      return {
        approved: this.options.defaultDecision === "allow",
        reason: `non-interactive terminal defaulted to ${this.options.defaultDecision}`
      };
    }

    const rl = readline.createInterface({ input, output });
    const prompt = formatApprovalPrompt(request);

    try {
      const answer = await withTimeout(rl.question(prompt), request.timeoutMs);
      const normalized = answer.trim().toLowerCase();
      const approved = normalized === "y" || normalized === "yes";
      return {
        approved,
        reason: approved ? "approved in terminal" : "denied in terminal",
        approver: "terminal"
      };
    } catch {
      return {
        approved: this.options.defaultDecision === "allow",
        reason: `approval timed out; defaulted to ${this.options.defaultDecision}`
      };
    } finally {
      rl.close();
    }
  }
}

export class StaticApprovalProvider implements ApprovalProvider {
  constructor(private readonly approved: boolean, private readonly reason = "static approval provider") {}

  async requestApproval(_request: ApprovalRequest): Promise<ApprovalDecision> {
    return {
      approved: this.approved,
      reason: this.reason,
      approver: "static"
    };
  }
}

export function createApprovalRequest(input: Omit<ApprovalRequest, "id">): ApprovalRequest {
  return {
    id: `approval_${randomUUID()}`,
    ...input
  };
}

function formatApprovalPrompt(request: ApprovalRequest): string {
  const lines = [
    "",
    "Palisade approval required",
    `Session: ${request.sessionId}`,
    request.server ? `Server: ${request.server}` : undefined,
    request.tool ? `Tool: ${request.tool}` : undefined,
    request.method ? `Method: ${request.method}` : undefined,
    `Reason: ${request.reason}`,
    request.taintIds.length > 0 ? `Taint: ${request.taintIds.join(", ")}` : undefined,
    `Summary: ${request.summary}`,
    "Allow this operation? [y/N] "
  ].filter(Boolean);
  return `${lines.join("\n")}`;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error("approval timed out")), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}
