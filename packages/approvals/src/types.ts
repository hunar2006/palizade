export interface ApprovalRequest {
  id: string;
  sessionId: string;
  server?: string | undefined;
  tool?: string | undefined;
  method?: string | undefined;
  reason: string;
  taintIds: string[];
  summary: string;
  details?: Record<string, unknown> | undefined;
  timeoutMs: number;
}

export interface ApprovalDecision {
  approved: boolean;
  reason: string;
  approver?: string | undefined;
}

export interface ApprovalProvider {
  requestApproval(request: ApprovalRequest): Promise<ApprovalDecision>;
}

export type ApprovalDefault = "allow" | "deny";
