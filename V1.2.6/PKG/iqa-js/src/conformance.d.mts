/** Independent conformance replay for the published IQA vector set. */

export interface ConformanceResult {
  checked: number;
  failures: string[];
  passed: number;
}

export interface ParsedForConformance {
  authority: string;
  action: string | null;
  shardHex: string;
}

/**
 * The independent RFC-009 §10 implementation used by the checker.
 * `buildFrame`-style helpers do not exist here: IQA v1.2.6 has no frame —
 * the derivation chain is URI → IQA_ROUTE (4 bytes).
 */
export declare function parseUri(uri: string): ParsedForConformance;

/** Replay a vector set. Accepts any object with the documented groups. */
export declare function runConformance(vectors: object): ConformanceResult;

/** Parse a vector set; defaults to the shipped one. */
export declare function loadVectors(path?: string): Record<string, unknown>;

/** Absolute path of the shipped vectors.json. */
export declare const DEFAULT_VECTORS_PATH: string;
