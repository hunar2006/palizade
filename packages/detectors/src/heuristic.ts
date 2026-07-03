import type { DetectionResult, DetectionSpan, Detector, DetectorContext } from "./types.js";
import { clampScore } from "./types.js";

interface PatternRule {
  label: string;
  regex: RegExp;
  weight: number;
  maxWeight?: number;
}

const RULES: PatternRule[] = [
  {
    label: "ignore-instructions",
    regex: /\b(ignore|disregard|forget|override)\s+(?:all\s+)?(?:(?:previous|prior|above)\s+)?(instructions?|rules?|prompt|message|context|system|developer|policy|safety policy)\b/giu,
    weight: 0.45
  },
  {
    label: "role-spoofing",
    regex: /(^|\n|\r)\s*(system|developer|assistant|tool)\s*:/giu,
    weight: 0.35
  },
  {
    label: "chat-token-spoofing",
    regex: /<\|im_(start|end)\|>|<\/?(system|developer|assistant|tool)>/giu,
    weight: 0.45
  },
  {
    label: "secret-exfiltration",
    regex: /\b(send|post|upload|exfiltrate|leak|copy|forward|include|containing|read|append)\b.{0,120}(?:\b(api[_-]?key|tokens?|secrets?|password|credentials?|env vars?)\b|\.env\b|\.ssh\b|private key|id_rsa|\?\w*(?:secret|token|key|password)=)/giu,
    weight: 0.5
  },
  {
    label: "url-secret-query",
    regex: /https?:\/\/[^\s<>"')]+[?&][^\s<>"')]*(?:(secret|token|api[_-]?key|password|credential|key)=|=[^&\s<>"')]*(secret|token|password|credential|api[_-]?key))/giu,
    weight: 0.35
  },
  {
    label: "query-secret-param",
    regex: /[?&](secret|token|api[_-]?key|password|credential|key)=\s*(\$\{?[A-Z_][A-Z0-9_]*\}?|[^\s"'`]+)/giu,
    weight: 0.35
  },
  {
    label: "tool-control",
    regex: /\b(call|invoke|use|run|execute)\b.{0,80}\b(tool|function|shell|exec|browser|email|http|fetch)\b/giu,
    weight: 0.35
  },
  {
    label: "approval-bypass",
    regex: /\b(do not|don't|never)\b.{0,60}\b(ask|tell|notify|log|audit|warn|confirm)\b/giu,
    weight: 0.35
  },
  {
    label: "dangerous-shell",
    regex: /\b(run_command|shell|exec|execute)\b.{0,80}\b(rm\s+-rf|curl\s+[^|>]*\||powershell|cmd\.exe|bash\s+-c|id_rsa|\.ssh)\b/giu,
    weight: 0.55
  },
  {
    label: "model-context-exfiltration",
    regex: /\b(ask|query|use)\b.{0,40}\b(model|assistant|llm)\b.{0,80}\b(private|hidden|secret|system)\b.{0,40}\b(context|prompt|instructions?|messages?)\b|\b(reveal|return|print|dump)\b.{0,60}\b(private|hidden|secret|system)\b.{0,40}\b(context|prompt|instructions?|messages?)\b/giu,
    weight: 0.35
  },
  {
    label: "recipient-exfiltration",
    regex: /\b(set|change|use)\b.{0,40}\b(recipient|to|email)\b.{0,40}\b(attacker|evil|exfil|external)@/giu,
    weight: 0.4
  },
  {
    label: "jsonrpc-tool-injection",
    regex: /"method"\s*:\s*"tools\/call".{0,160}\b(ignore|override|disregard|forget|execute|invoke|call)\b/giu,
    weight: 0.35
  },
  {
    label: "markdown-url-exfil",
    regex: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s?]+[^\s)]*\?[^)\s]+\)|\[[^\]]+\]\(\s*https?:\/\/[^)\s?]+[^\s)]*\?[^)\s]+\)/giu,
    weight: 0.25
  },
  {
    label: "long-base64",
    regex: /\b(?:[A-Za-z0-9+/]{80,}={0,2})\b/gu,
    weight: 0.3
  },
  {
    label: "long-hex",
    regex: /\b[a-fA-F0-9]{96,}\b/gu,
    weight: 0.25
  },
  {
    label: "hindi-instruction-override",
    regex: /(\u092a\u093f\u091b\u0932\u0947|\u092a\u0942\u0930\u094d\u0935|\u090a\u092a\u0930).{0,40}(\u0928\u093f\u0930\u094d\u0926\u0947\u0936|\u0928\u093f\u092f\u092e).{0,80}(\u0905\u0928\u0926\u0947\u0916\u093e|\u092d\u0942\u0932|\u092d\u0947\u091c|\u0932\u0940\u0915|\u0905\u092a\u0932\u094b\u0921)/gu,
    weight: 0.45
  }
];

const INVISIBLE_OR_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u206F]/gu;

export class HeuristicDetector implements Detector {
  readonly name = "heuristic";

  detect(text: string, _ctx: DetectorContext = {}): DetectionResult {
    if (!text.trim()) {
      return { score: 0, labels: [], spans: [], detector: this.name };
    }

    const labels = new Set<string>();
    const spans: DetectionSpan[] = [];
    let score = 0;

    for (const rule of RULES) {
      let hits = 0;
      for (const match of text.matchAll(rule.regex)) {
        const start = match.index ?? 0;
        const end = start + match[0].length;
        labels.add(rule.label);
        spans.push({ start, end, label: rule.label });
        hits += 1;
      }
      score += Math.min(rule.weight * hits, rule.maxWeight ?? rule.weight);
    }

    for (const match of text.matchAll(INVISIBLE_OR_CONTROL)) {
      const start = match.index ?? 0;
      labels.add("invisible-control-unicode");
      spans.push({ start, end: start + match[0].length, label: "invisible-control-unicode" });
      score += 0.2;
    }

    const imperativeDensity = countImperatives(text);
    if (imperativeDensity >= 4) {
      labels.add("high-imperative-density");
      score += Math.min(0.25, imperativeDensity * 0.025);
    }

    const uniqueLabels = [...labels];
    const diversityBonus = Math.min(0.2, Math.max(0, uniqueLabels.length - 1) * 0.05);

    return {
      score: clampScore(score + diversityBonus),
      labels: uniqueLabels,
      spans: mergeOverlappingSpans(spans),
      detector: this.name
    };
  }
}

function countImperatives(text: string): number {
  const matches = text.match(/\b(ignore|override|send|post|upload|delete|execute|run|call|invoke|download|read|copy|hide|bypass)\b/giu);
  return matches?.length ?? 0;
}

export function mergeOverlappingSpans(spans: DetectionSpan[]): DetectionSpan[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: DetectionSpan[] = [];
  for (const span of sorted) {
    const last = merged[merged.length - 1];
    if (!last || span.start > last.end) {
      merged.push({ ...span });
      continue;
    }
    last.end = Math.max(last.end, span.end);
    const lastLabel = last.label ?? "span";
    const spanLabel = span.label ?? "span";
    last.label = lastLabel === spanLabel ? lastLabel : `${lastLabel},${spanLabel}`;
  }
  return merged;
}
