/** Nominal type branding helper. */
export type Brand<TValue, TBrand extends string> = TValue & { readonly __brand: TBrand };

/** Hex-encoded hash string. */
export type Hash = Brand<string, 'Hash'>;

/** Chain address (format depends on network). */
export type Address = Brand<string, 'Address'>;

/** RFC3339 timestamp (as emitted by chrono serde). */
export type Rfc3339Timestamp = Brand<string, 'Rfc3339Timestamp'>;
