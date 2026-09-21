#!/usr/bin/env node
// iqa — replay the published conformance vectors. [PASS] or it is not.
//
//   npx @aicent/iqa                       # replay the shipped vectors
//   npx @aicent/iqa --vectors ./new.json  # replay a different vector set
//   npx @aicent/iqa --json                # machine-readable output

import { runConformance, loadVectors, DEFAULT_VECTORS_PATH } from '../src/conformance.mjs';

const args = process.argv.slice(2);

let vectorsPath = DEFAULT_VECTORS_PATH;
let json = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--vectors') {
    vectorsPath = args[++i];
    if (!vectorsPath) {
      console.error('error: --vectors requires a path');
      process.exit(2);
    }
  } else if (args[i] === '--json') {
    json = true;
  } else if (args[i] === '--help' || args[i] === '-h') {
    console.log('@aicent/iqa — replay the published conformance vectors (RFC-009 §10/§11)');
    console.log('  npx @aicent/iqa                       replay the shipped vectors');
    console.log('  npx @aicent/iqa --vectors ./new.json  replay a different vector set');
    console.log('  npx @aicent/iqa --json                machine-readable output');
    process.exit(0);
  } else {
    console.error(`error: unknown argument ${args[i]}`);
    process.exit(2);
  }
}

let vectors;
try {
  vectors = loadVectors(vectorsPath);
} catch (err) {
  console.error(`error: cannot load vectors (${err.message})`);
  process.exit(2);
}

const result = runConformance(vectors);

if (json) {
  console.log(JSON.stringify({
    checked: result.checked,
    passed: result.passed,
    failures: result.failures,
    vectors: vectorsPath,
  }, null, 2));
} else {
  console.log(`iqa conformance replay — spec ${vectors.spec ?? '(unlabeled)'}`);
  for (const f of result.failures) console.log(`[FAIL] ${f}`);
  console.log(`[PASS] all ${result.checked} checks passed`);
}

process.exit(result.failures.length === 0 ? 0 : 1);
