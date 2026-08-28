/**
 * Entry point for the single-executable build.
 *
 * CommonJS has no top-level await, hence the promise chain rather than the
 * `await main()` that run.ts uses.
 */

import { main } from './main.ts';

void main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`openp2s: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  },
);
