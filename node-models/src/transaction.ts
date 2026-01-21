import type { Address, Hash, Rfc3339Timestamp } from './common.js';

export type TransactionStatus = 'confirmed' | 'processing' | 'queued' | 'not_found' | 'included' | 'pending' | 'finalized';

export interface Transaction {
  readonly tx_id: Hash;
  readonly sender: Address;
  readonly recipient: Address;
  readonly amount: number;
  readonly fee: number;
  readonly nonce: number;
  /** RFC3339 */
  readonly timestamp: Rfc3339Timestamp;
  readonly signature: string;
}

export interface GetTransactionResult {
  readonly tx_id: Hash;
  readonly sender?: Address;
  readonly recipient?: Address;
  readonly amount?: number;
  readonly fee?: number;
  readonly nonce?: number;
  readonly timestamp?: Rfc3339Timestamp;
  readonly signature?: string;
  readonly status: TransactionStatus;
  readonly message?: string;
}

export interface TransactionHistoryEntry {
  readonly tx_id: Hash;
  readonly sender: Address;
  readonly recipient: Address;
  readonly amount: number;
  readonly fee: number;
  readonly nonce: number;
  readonly timestamp: string;
  readonly status: string;
  readonly direction: 'incoming' | 'outgoing' | 'external';
  readonly block_number: number;
  readonly block_hash: string;
  readonly transaction_index: number;
}

export interface TransactionHistoryResult {
  readonly address: Address;
  readonly transactions: readonly TransactionHistoryEntry[];
  readonly has_more: boolean;
  readonly next_cursor: string | null;
}
