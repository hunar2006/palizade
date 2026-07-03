import type { DetectionResult, Detector, DetectorContext } from "./types.js";
import { clampScore } from "./types.js";

export class DetectorPipeline implements Detector {
  readonly name = "pipeline";

  constructor(private readonly detectors: Detector[]) {}

  async detect(text: string, ctx?: DetectorContext): Promise<DetectionResult> {
    const results = await Promise.all(this.detectors.map((detector) => detector.detect(text, ctx)));
    return fuseDetections(results);
  }
}

export function fuseDetections(results: DetectionResult[]): DetectionResult {
  if (results.length === 0) {
    return { score: 0, labels: [], spans: [], detector: "pipeline" };
  }

  const labels = new Set<string>();
  const spans = [];
  let maxScore = 0;
  let additiveSignal = 0;
  const detectors: string[] = [];

  for (const result of results) {
    maxScore = Math.max(maxScore, result.score);
    additiveSignal += result.score * 0.15;
    for (const label of result.labels) {
      labels.add(label);
    }
    if (result.spans) {
      spans.push(...result.spans);
    }
    if (result.detector) {
      detectors.push(result.detector);
    }
  }

  return {
    score: clampScore(maxScore + additiveSignal),
    labels: [...labels],
    spans,
    detector: detectors.length > 0 ? detectors.join("+") : "pipeline"
  };
}
