export interface SessionState {
  seenUntrusted: boolean;
  seenSensitive: boolean;
  exposureExpiresAt?: number | undefined;
  trustedDestinations: string[];
  quarantine?: { expiresAt: number; remainingTurns: number } | undefined;
  sinkCalls?: number[];
  destinations?: string[];
  repeats?: Record<string, number>;
  trackingOverflow?: boolean;
}

export function emptySession(): SessionState {
  return { seenUntrusted: false, seenSensitive: false, trustedDestinations: [] };
}

export function expireExposure(state: SessionState, ttlMs: number, now = Date.now()): SessionState {
  if (!state.seenUntrusted && !state.seenSensitive) return state;
  // Pre-TTL session rows get one bounded grace period when first observed.
  if (state.exposureExpiresAt === undefined) return { ...state, exposureExpiresAt: now + ttlMs };
  if (state.exposureExpiresAt > now) return state;
  return { ...state, seenUntrusted: false, seenSensitive: false, exposureExpiresAt: undefined };
}
