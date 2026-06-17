import type { ScanResult } from '../types.js';

/** Serialize a scan result as pretty-printed JSON. */
export function toJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
