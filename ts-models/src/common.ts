/**
 * Nominal type branding helper to distinguish hashes and addresses at compile time.
 */
export type Brand<TValue, TBrand extends string> = TValue & { readonly __brand: TBrand };

/** Hex-encoded 32 byte hash (lowercase, no 0x prefix). */
export type Hash = Brand<string, 'Hash'>;

/** Bech32 or base58 encoded account identifier (network specific). */
export type AccountAddress = Brand<string, 'AccountAddress'>;

/** UNIX epoch timestamp in milliseconds. */
export type UnixMs = Brand<number, 'UnixMs'>;

/** Positive integer constrained to 53-bit safe range. */
export type PositiveInteger = Brand<number, 'PositiveInteger'>;

/** 64-bit fixed precision value representing coins at atto precision. */
export type AttoValue = Brand<number, 'AttoValue'>;

export type CommitteeId = Brand<string, 'CommitteeId'>;

export interface PaginationWindow {
  readonly fromHeight: PositiveInteger;
  readonly toHeight: PositiveInteger;
}
