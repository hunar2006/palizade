import { z } from "zod";

export const auditEventSchema = z.object({
  event_id: z.string().optional(),
  ts: z.string(),
  profile_id: z.string().optional(),
  scope_id: z.string().optional(),
  run_id: z.string().optional(),
  session: z.string(),
  server: z.string().optional(),
  tool: z.string().optional(),
  direction: z.enum(["request", "response", "internal"]),
  method: z.string().optional(),
  taint_ids: z.array(z.string()).default([]),
  detector: z.object({
    score: z.number().min(0).max(1).default(0),
    labels: z.array(z.string()).default([])
  }).default({ score: 0, labels: [] }),
  matched_rule: z.object({
    id: z.string().optional(),
    name: z.string().optional()
  }).optional(),
  action: z.string(),
  reason: z.string().optional(),
  event_hash: z.string().optional(),
  previous_event_hash: z.string().optional(),
  latency_ms: z.number().nonnegative().default(0),
  payload_hash: z.string().optional(),
  raw_payload: z.unknown().optional(),
  metadata: z.record(z.string(), z.unknown()).optional()
});

export type AuditEvent = z.infer<typeof auditEventSchema>;

export interface AuditWriteEvent {
  ts?: string | undefined;
  event_id?: string | undefined;
  profile_id?: string | undefined;
  scope_id?: string | undefined;
  run_id?: string | undefined;
  session: string;
  server?: string | undefined;
  tool?: string | undefined;
  direction: "request" | "response" | "internal";
  method?: string | undefined;
  taint_ids?: string[] | undefined;
  detector?: { score: number; labels: string[] } | undefined;
  matched_rule?: { id?: string | undefined; name?: string | undefined } | undefined;
  action: string;
  reason?: string | undefined;
  event_hash?: string | undefined;
  previous_event_hash?: string | undefined;
  latency_ms?: number | undefined;
  payload_hash?: string | undefined;
  raw_payload?: unknown;
  metadata?: Record<string, unknown> | undefined;
  payload?: unknown;
}

export interface AuditQuery {
  since?: Date | undefined;
  action?: string | undefined;
  session?: string | undefined;
  server?: string | undefined;
  tool?: string | undefined;
  limit?: number | undefined;
}

export interface AuditSink {
  write(event: AuditEvent): Promise<void>;
  query?(query: AuditQuery): Promise<AuditEvent[]>;
  close?(): Promise<void> | void;
}
