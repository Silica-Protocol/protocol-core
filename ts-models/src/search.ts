import type { AccountAddress, Hash } from './common.js';

export type SearchResultType = 'block' | 'transaction' | 'account';

export interface SearchResultItem {
  readonly type: SearchResultType;
  readonly id: Hash | AccountAddress;
  readonly title: string;
  readonly subtitle: string;
  readonly score: number;
  readonly route: readonly string[];
  readonly highlight?: string;
}

export interface SearchQuery {
  readonly term: string;
  readonly limit?: number;
}

export interface SearchResponse {
  readonly items: readonly SearchResultItem[];
}
