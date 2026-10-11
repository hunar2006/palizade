export interface SessionState {
  seenUntrusted: boolean;
  seenSensitive: boolean;
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
