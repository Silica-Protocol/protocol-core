import type { PositiveInteger, UnixMs } from './common.js';

export interface NetworkStatistics {
  readonly currentHeight: PositiveInteger;
  readonly finalizedHeight: PositiveInteger;
  readonly averageTps: number;
  readonly activeValidators: number;
  readonly nextElectionEtaMs: number;
  readonly timestamp: UnixMs;
}

export interface FinalityLagMetrics {
  readonly maxLag: PositiveInteger;
  readonly minLag: PositiveInteger;
  readonly medianLag: PositiveInteger;
  readonly sampleSize: number;
  readonly timestamp: UnixMs;
}

export interface NetworkHealthSnapshot {
  readonly throughput: number;
  readonly latency: number;
  readonly finalityLag: FinalityLagMetrics;
  readonly timestamp: UnixMs;
}
