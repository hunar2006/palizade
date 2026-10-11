export interface SessionState {
  seenUntrusted: boolean;
  seenSensitive: boolean;
  trustedDestinations: string[];
  quarantine?: { expiresAt: number; remainingTurns: number } | undefined;
}

export function emptySession(): SessionState {
  return { seenUntrusted: false, seenSensitive: false, trustedDestinations: [] };
}
