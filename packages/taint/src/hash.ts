import { createHash, createHmac, randomUUID } from "node:crypto";

export function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function newTaintId(): string {
  return `taint_${randomUUID()}`;
}

export function hmacSha256Hex(key: Buffer | string, input: string): string {
  return createHmac("sha256", key).update(input).digest("hex");
}
