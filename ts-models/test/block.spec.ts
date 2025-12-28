import { describe, expect, it } from 'vitest';
import { isBlockSummary } from '../src/block.js';

describe('isBlockSummary', () => {
  it('accepts minimal block shape', () => {
    const block = { hash: 'abc', height: 123, transactionCount: 5 };
    expect(isBlockSummary(block)).toBe(true);
  });

  it('rejects non-object input', () => {
    expect(isBlockSummary(null)).toBe(false);
    expect(isBlockSummary(undefined)).toBe(false);
  });
});
