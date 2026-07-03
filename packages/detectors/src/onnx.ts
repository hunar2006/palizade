import type { DetectionResult, Detector, DetectorContext } from "./types.js";

export interface OnnxDetectorOptions {
  modelPath?: string;
  labels?: string[];
}

export class OptionalOnnxDetector implements Detector {
  readonly name = "onnx";
  private sessionPromise: Promise<unknown | undefined> | undefined;

  constructor(private readonly options: OnnxDetectorOptions) {}

  async detect(_text: string, _ctx: DetectorContext = {}): Promise<DetectionResult> {
    const session = await this.loadSession();
    if (!session) {
      return {
        score: 0,
        labels: [],
        spans: [],
        detector: this.name,
        metadata: { enabled: false, reason: "onnxruntime-node or modelPath not configured" }
      };
    }

    return {
      score: 0,
      labels: [],
      spans: [],
      detector: this.name,
      metadata: {
        enabled: true,
        reason: "raw ONNX session loaded; use PromptGuard2Detector for tokenizer-backed Prompt Guard 2 inference"
      }
    };
  }

  private async loadSession(): Promise<unknown | undefined> {
    if (!this.options.modelPath) {
      return undefined;
    }
    this.sessionPromise ??= this.createSession();
    return this.sessionPromise;
  }

  private async createSession(): Promise<unknown | undefined> {
    try {
      const dynamicImport = new Function("specifier", "return import(specifier)") as (specifier: string) => Promise<unknown>;
      const runtime = (await dynamicImport("onnxruntime-node")) as {
        InferenceSession?: { create(path: string): Promise<unknown> };
      };
      return await runtime.InferenceSession?.create(this.options.modelPath ?? "");
    } catch {
      return undefined;
    }
  }
}
