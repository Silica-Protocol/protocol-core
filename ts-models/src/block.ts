import type { AccountAddress, AttoValue, Hash, PositiveInteger, UnixMs, CommitteeId } from './common.js';
import type { TransactionSummary } from './transaction.js';

export type BlockStatus = 'pending' | 'finalized';

export interface BlockSummary {
  readonly height: PositiveInteger;
  readonly hash: Hash;
  readonly parentHash: Hash | null;
  readonly timestamp: UnixMs;
  readonly transactionCount: number;
  readonly totalValue: AttoValue;
  readonly status: BlockStatus;
  readonly confirmationScore: number;
  readonly miner: AccountAddress;
  readonly delegateSet: readonly CommitteeId[];
}

export interface BlockDetails extends BlockSummary {
  readonly transactions: readonly TransactionSummary[];
}

export interface BlockListRequest {
  readonly limit: number;
  readonly pagination?: {
    readonly before?: PositiveInteger;
    readonly after?: PositiveInteger;
  };
}

export interface BlockListResponse {
  readonly items: readonly BlockSummary[];
  readonly next?: PositiveInteger;
  readonly prev?: PositiveInteger;
}

export const isBlockSummary = (value: unknown): value is BlockSummary => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  const hash = candidate['hash'];
  const height = candidate['height'];
  const transactionCount = candidate['transactionCount'];

  return (
    typeof hash === 'string' &&
    typeof height === 'number' &&
    typeof transactionCount === 'number'
  );
};
