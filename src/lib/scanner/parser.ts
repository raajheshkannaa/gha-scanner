import { parse } from 'yaml';

const MAX_FILE_SIZE = 1_000_000; // 1MB
const MAX_ALIAS_COUNT = 10;

export interface ParseResult {
  parsed: Record<string, unknown> | null;
  error: string | null;
}

/**
 * Safely parse a YAML workflow file with size limits and alias restrictions.
 * Returns null parsed value with error message on failure (never throws).
 */
export function parseWorkflowYaml(content: string, filename: string): ParseResult {
  // Size check before parsing
  if (content.length > MAX_FILE_SIZE) {
    return {
      parsed: null,
      error: `${filename}: File exceeds 1MB size limit (${(content.length / 1_000_000).toFixed(1)}MB)`,
    };
  }

  try {
    const parsed = parse(content, {
      maxAliasCount: MAX_ALIAS_COUNT,
      strict: false,
    });

    if (parsed === null || parsed === undefined || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {
        parsed: null,
        error: `${filename}: Not a valid YAML object`,
      };
    }

    return { parsed: parsed as Record<string, unknown>, error: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown parse error';
    return {
      parsed: null,
      error: `${filename}: YAML parse error: ${message}`,
    };
  }
}

/**
 * Find line number for a given key path in YAML content.
 * Uses simple text search for position info.
 */
export function findLineNumber(content: string, searchText: string): number | undefined {
  const idx = content.indexOf(searchText);
  if (idx === -1) return undefined;
  let line = 1;
  for (let i = 0; i < idx; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}
