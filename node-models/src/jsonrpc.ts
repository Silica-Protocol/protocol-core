export interface JsonRpcRequest<TParams = unknown> {
  readonly jsonrpc: '2.0';
  readonly method: string;
  readonly params?: TParams;
  readonly id: string | number | null;
}

export interface JsonRpcError {
  readonly code: number;
  readonly message: string;
  readonly data?: unknown;
}

export interface JsonRpcResponse<TResult = unknown> {
  readonly jsonrpc: '2.0';
  readonly result?: TResult;
  readonly error?: JsonRpcError;
  readonly id: string | number | null;
}
