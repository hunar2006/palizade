export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcSuccess {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result: unknown;
}

export interface JsonRpcFailure {
  jsonrpc: "2.0";
  id: JsonRpcId;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;
export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse;
export type JsonRpcEnvelope = JsonRpcMessage | JsonRpcMessage[];

export interface McpTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
  icons?: unknown[];
}

export interface ToolsListResult {
  tools?: McpTool[];
}

export interface ToolsCallParams {
  name?: string;
  arguments?: unknown;
}

export function isRequest(message: JsonRpcMessage): message is JsonRpcRequest {
  return "method" in message;
}

export function isResponse(message: JsonRpcMessage): message is JsonRpcResponse {
  return "id" in message && !("method" in message);
}

export function isSuccess(message: JsonRpcMessage): message is JsonRpcSuccess {
  return isResponse(message) && "result" in message;
}

export function makeErrorResponse(id: JsonRpcId | undefined, code: number, message: string, data?: unknown): JsonRpcFailure {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: {
      code,
      message,
      ...(data === undefined ? {} : { data })
    }
  };
}
