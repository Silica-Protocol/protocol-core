import type { AccountAddress, AttoValue, Hash, PositiveInteger, UnixMs } from './common.js';
import type { BlockSummary } from './block.js';
import type { TransactionSummary } from './transaction.js';

export interface AccountSummary {
  readonly address: AccountAddress;
  readonly balance: AttoValue;
  readonly stakedBalance: AttoValue;
  readonly nonce: PositiveInteger;
  readonly reputation: number;
  readonly lastSeen: UnixMs;
}

export interface AccountActivitySnapshot {
  readonly account: AccountSummary;
  readonly outbound: readonly TransactionSummary[];
  readonly inbound: readonly TransactionSummary[];
  readonly recentBlocks: readonly BlockSummary[];
}

export interface AccountLookupRequest {
  readonly address: AccountAddress;
}

export interface AccountLookupResponse {
  readonly account: AccountSummary | null;
  readonly recentActivity?: AccountActivitySnapshot;
}

export interface DelegatorBreakdown {
  readonly delegate: AccountAddress;
  readonly totalStake: AttoValue;
  readonly delegatorCount: number;
}

export interface AccountStakeDistribution {
  readonly epoch: PositiveInteger;
  readonly items: readonly DelegatorBreakdown[];
}
