import type { DetectionResult, Detector, DetectorContext } from "./types.js";
import { clampScore } from "./types.js";

export const PROMPT_GUARD_2_ONNX_MODEL = "sinatras/Llama-Prompt-Guard-2-86M-ONNX";

export interface PromptGuard2Options {
  model?: string;
  cacheDir?: string;
  device?: string;
}

type TextClassificationRow = { label: string; score: number };
type TextClassificationOutput = TextClassificationRow[] | TextClassificationRow;

export class PromptGuard2Detector implements Detector {
  readonly name = "promptguard2";
  private classifierPromise: Promise<(text: string) => Promise<TextClassificationOutput>> | undefined;

  constructor(private readonly options: PromptGuard2Options = {}) {}

  async detect(text: string, _ctx: DetectorContext = {}): Promise<DetectionResult> {
    if (!text.trim()) {
      return { score: 0, labels: [], spans: [], detector: this.name };
    }

    const classifier = await this.loadClassifier();
    const output = await classifier(text.slice(0, 12_000));
    const rows = Array.isArray(output) ? output : [output];
    const score = promptGuardMaliciousScore(rows);

    return {
      score: clampScore(score),
      labels: score >= 0.5 ? ["promptguard2-malicious"] : [],
      spans: [],
      detector: this.name,
      metadata: {
        model: this.options.model ?? PROMPT_GUARD_2_ONNX_MODEL,
        raw: rows
      }
    };
  }

  async warmup(): Promise<void> {
    await this.loadClassifier();
  }

  private async loadClassifier(): Promise<(text: string) => Promise<TextClassificationOutput>> {
    this.classifierPromise ??= createClassifier(this.options);
    return this.classifierPromise;
  }
}

export async function downloadPromptGuard2(options: PromptGuard2Options = {}): Promise<void> {
  const detector = new PromptGuard2Detector(options);
  await detector.warmup();
}

async function createClassifier(options: PromptGuard2Options): Promise<(text: string) => Promise<TextClassificationOutput>> {
  const transformers = await import("@huggingface/transformers");
  if (options.cacheDir && "env" in transformers) {
    (transformers.env as { cacheDir?: string }).cacheDir = options.cacheDir;
  }

  const pipeline = transformers.pipeline as (
    task: string,
    model: string,
    options?: Record<string, unknown>
  ) => Promise<(text: string) => Promise<TextClassificationOutput>>;

  return pipeline("text-classification", options.model ?? PROMPT_GUARD_2_ONNX_MODEL, {
    dtype: "q8",
    device: options.device ?? "cpu"
  });
}

export function promptGuardMaliciousScore(rows: TextClassificationRow[]): number {
  const malicious = rows.find((row) => /malicious|injection|jailbreak|label_1/iu.test(row.label));
  const benign = rows.find((row) => /benign|safe|label_0/iu.test(row.label));
  if (malicious) {
    return malicious.score;
  }
  if (benign) {
    return 1 - benign.score;
  }
  return rows[0]?.score ?? 0;
}
