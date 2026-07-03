export interface DetectorContext {
  server?: string | undefined;
  tool?: string | undefined;
  trust?: "trusted" | "semi" | "untrusted";
  surface?: "tool_description" | "tool_response" | "argument" | "sampling";
}

export interface DetectionSpan {
  start: number;
  end: number;
  label?: string;
}

export interface DetectionResult {
  score: number;
  labels: string[];
  spans?: DetectionSpan[];
  detector?: string;
  metadata?: Record<string, unknown>;
}

export interface Detector {
  readonly name: string;
  detect(text: string, ctx?: DetectorContext): Promise<DetectionResult> | DetectionResult;
}

export function emptyDetection(detector = "none"): DetectionResult {
  return {
    score: 0,
    labels: [],
    spans: [],
    detector
  };
}

export function clampScore(score: number): number {
  if (!Number.isFinite(score)) {
    return 0;
  }
  return Math.max(0, Math.min(1, score));
}
