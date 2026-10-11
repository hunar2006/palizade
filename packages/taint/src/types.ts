import type { SessionState } from "./session.js";
export type TrustLevel = "trusted" | "semi" | "untrusted";
export type TaintScope = "process" | "profile" | "external_run_id";
export type TaintClass = "untrusted" | "sensitive";

export interface TaintFingerprint {
  normalized: string;
  substrings: string[];
  tokens: string[];
  simhash: string;
  sensitiveFragments?: string[];
}

export interface TaintRecord {
  id: string;
  profileId?: string | undefined;
  scopeId?: string | undefined;
  runId?: string | undefined;
  sessionId: string;
  sourceServer: string;
  sourceTool: string;
  trust: TrustLevel;
  createdAt: string;
  expiresAt?: string | undefined;
  payloadHash: string;
  persistent?: boolean;
  provenanceIds?: string[];
  detectorScore: number;
  labels: string[];
  classes: TaintClass[];
  fingerprint: TaintFingerprint;
}

export interface TaintMatch {
  taintId: string;
  reason: "substring" | "token" | "fuzzy" | "temporal" | `decoded:${string}`;
  classes?: TaintClass[] | undefined;
  token?: string;
  score?: number;
}

export interface AddTaintInput {
  persistent?: boolean;
  provenanceIds?: string[];
  profileId?: string | undefined;
  scopeId?: string | undefined;
  runId?: string | undefined;
  sessionId: string;
  sourceServer: string;
  sourceTool: string;
  trust: TrustLevel;
  text: string;
  detectorScore: number;
  labels: string[];
  classes?: TaintClass[] | undefined;
}

export interface TaintMatchOptions {
  persistentOnly?: boolean;
  sensitiveFragments?: boolean;
  fuzzyHammingMax?: number;
  minNormalizedLength?: number;
  classes?: TaintClass[] | undefined;
}

export interface TaintStore {
  promotePersistent(id: string): void;
  getSession(sessionId: string): SessionState;
  updateSession(sessionId: string, update: (state: SessionState) => SessionState): SessionState;
  destinationKey(text: string): string;
  add(input: AddTaintInput): TaintRecord;
  get(id: string): TaintRecord | undefined;
  all(): TaintRecord[];
  match(sessionId: string, text: string, options?: TaintMatchOptions): TaintMatch[];
  markTemporal(sessionId: string, sourceTaintIds: string[], config: TemporalTaintConfig): void;
  consumeTurn(sessionId: string): void;
  hasTemporal(sessionId: string): boolean;
}

export interface TemporalTaintConfig {
  enabled: boolean;
  turns: number;
  ttlMs: number;
  detectorScoreGte: number;
}

export interface TemporalTaintState {
  sessionId: string;
  sourceTaintIds: string[];
  expiresAt: number;
  remainingTurns: number;
}
