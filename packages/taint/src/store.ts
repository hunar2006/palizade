import { makeFingerprint, hammingDistanceHex, normalizeText } from "./fingerprint.js";
import { newTaintId, sha256 } from "./hash.js";
import type { AddTaintInput, TaintClass, TaintMatch, TaintMatchOptions, TaintRecord, TaintStore, TemporalTaintConfig, TemporalTaintState } from "./types.js";

export class InMemoryTaintStore implements TaintStore {
  private readonly records = new Map<string, TaintRecord>();
  private readonly temporalBySession = new Map<string, TemporalTaintState>();

  add(input: AddTaintInput): TaintRecord {
    const record: TaintRecord = {
      id: newTaintId(),
      sessionId: input.sessionId,
      sourceServer: input.sourceServer,
      sourceTool: input.sourceTool,
      trust: input.trust,
      createdAt: new Date().toISOString(),
      payloadHash: sha256(input.text),
      detectorScore: input.detectorScore,
      labels: [...input.labels],
      classes: normalizeClasses(input.classes),
      fingerprint: makeFingerprint(input.text)
    };
    this.records.set(record.id, record);
    return record;
  }

  get(id: string): TaintRecord | undefined {
    return this.records.get(id);
  }

  all(): TaintRecord[] {
    return [...this.records.values()];
  }

  match(sessionId: string, text: string, options: TaintMatchOptions = {}): TaintMatch[] {
    const normalized = normalizeText(text);
    const incoming = makeFingerprint(text);
    const minNormalizedLength = options.minNormalizedLength ?? 16;
    const fuzzyHammingMax = options.fuzzyHammingMax ?? 7;
    const matches: TaintMatch[] = [];

    for (const record of this.records.values()) {
      if (record.sessionId !== sessionId) {
        continue;
      }
      if (!matchesClassFilter(record.classes, options.classes)) {
        continue;
      }

      const substring = record.fingerprint.substrings.find((candidate) => candidate.length >= minNormalizedLength && normalized.includes(candidate));
      if (substring) {
        matches.push({ taintId: record.id, reason: "substring", token: substring, classes: record.classes });
        continue;
      }

      const token = record.fingerprint.tokens.find((candidate) => candidate.length >= 8 && incoming.tokens.includes(candidate));
      if (token) {
        matches.push({ taintId: record.id, reason: "token", token, classes: record.classes });
        continue;
      }

      if (record.fingerprint.normalized.length >= 32 && incoming.normalized.length >= 32) {
        const distance = hammingDistanceHex(record.fingerprint.simhash, incoming.simhash);
        if (distance <= fuzzyHammingMax) {
          matches.push({
            taintId: record.id,
            reason: "fuzzy",
            classes: record.classes,
            score: 1 - distance / 64
          });
        }
      }
    }

    const temporal = this.temporalBySession.get(sessionId);
    if (temporal && temporal.expiresAt > Date.now() && temporal.remainingTurns > 0) {
      for (const taintId of temporal.sourceTaintIds) {
        const record = this.records.get(taintId);
        const classes = record?.classes ?? ["untrusted"];
        if (matchesClassFilter(classes, options.classes)) {
          matches.push({ taintId, reason: "temporal", classes });
        }
      }
    }

    return dedupeMatches(matches);
  }

  markTemporal(sessionId: string, sourceTaintIds: string[], config: TemporalTaintConfig): void {
    if (!config.enabled || sourceTaintIds.length === 0) {
      return;
    }
    this.temporalBySession.set(sessionId, {
      sessionId,
      sourceTaintIds: [...new Set(sourceTaintIds)],
      expiresAt: Date.now() + config.ttlMs,
      remainingTurns: config.turns
    });
  }

  consumeTurn(sessionId: string): void {
    const temporal = this.temporalBySession.get(sessionId);
    if (!temporal) {
      return;
    }
    if (temporal.expiresAt <= Date.now() || temporal.remainingTurns <= 0) {
      this.temporalBySession.delete(sessionId);
      return;
    }
    temporal.remainingTurns -= 1;
    if (temporal.remainingTurns <= 0) {
      this.temporalBySession.delete(sessionId);
    }
  }

  hasTemporal(sessionId: string): boolean {
    const temporal = this.temporalBySession.get(sessionId);
    if (!temporal) {
      return false;
    }
    if (temporal.expiresAt <= Date.now() || temporal.remainingTurns <= 0) {
      this.temporalBySession.delete(sessionId);
      return false;
    }
    return true;
  }
}

function normalizeClasses(classes: TaintClass[] | undefined): TaintClass[] {
  const normalized: TaintClass[] = classes && classes.length > 0 ? classes : ["untrusted"];
  return [...new Set<TaintClass>(normalized)];
}

function matchesClassFilter(classes: TaintClass[], filter: TaintClass[] | undefined): boolean {
  return !filter || filter.some((taintClass) => classes.includes(taintClass));
}

function dedupeMatches(matches: TaintMatch[]): TaintMatch[] {
  const seen = new Set<string>();
  const deduped: TaintMatch[] = [];
  for (const match of matches) {
    const key = `${match.taintId}:${match.reason}:${match.token ?? ""}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(match);
    }
  }
  return deduped;
}
