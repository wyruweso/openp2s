#!/usr/bin/env node
/**
 * Development entry point. Node runs this directly with type stripping.
 *
 * Separate from main.ts so that stays a pure module: the single-executable
 * build bundles to CommonJS and cannot express top-level await.
 */

import { main } from './main.ts';

process.exitCode = await main();
