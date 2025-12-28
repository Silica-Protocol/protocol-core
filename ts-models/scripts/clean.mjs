#!/usr/bin/env node
import { rmSync } from 'node:fs';
import { resolve } from 'node:path';

const target = resolve(new URL('.', import.meta.url).pathname, '..', 'dist');

try {
  rmSync(target, { recursive: true, force: true });
} catch (error) {
  console.error('Failed to clean dist directory:', error);
  process.exitCode = 1;
}
