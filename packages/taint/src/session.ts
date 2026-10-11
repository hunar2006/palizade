export interface SessionState {
  seenUntrusted: boolean;
  seenSensitive: boolean;
  trustedDestinations: string[];
}

export function emptySession(): SessionState {
  return { seenUntrusted: false, seenSensitive: false, trustedDestinations: [] };
}
