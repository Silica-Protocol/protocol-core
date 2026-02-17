import type { Address, Hash, Rfc3339Timestamp } from './common.js';
import type { Transaction } from './transaction.js';

export interface Block {
  readonly block_number: number;
  readonly block_hash: Hash;
  readonly previous_block_hash: Hash;
  readonly transactions: readonly Transaction[];
  readonly timestamp: Rfc3339Timestamp;
  readonly validator_address: Address;
  readonly gas_used: number;
  readonly gas_limit: number;
  readonly state_root?: unknown;
  readonly state_leaf_count?: number;
  readonly shard_commitments?: unknown;
}

export interface GetBlocksResult {
  readonly blocks: readonly Block[];
  readonly next_cursor?: number;
}
