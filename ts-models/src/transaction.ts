import type { AccountAddress, AttoValue, Hash, PositiveInteger, UnixMs } from './common.js';

export type TransactionStatus = 'pending' | 'confirmed' | 'rejected';

export interface TransactionSummary {
  readonly hash: Hash;
  readonly blockHash: Hash;
  readonly blockHeight: PositiveInteger;
  readonly from: AccountAddress;
  readonly to: AccountAddress;
  readonly value: AttoValue;
  readonly fee: AttoValue;
  readonly timestamp: UnixMs;
  readonly status: TransactionStatus;
  readonly memo?: string;
}

export interface TransactionDetails extends TransactionSummary {
  readonly inputs: readonly Hash[];
  readonly outputs: readonly Hash[];
  readonly confirmations: number;
}
