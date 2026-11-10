import type { Finding, Rule, SourceFile } from "../types.js";

const CODE_EXT = /\.(m|c)?(j|t)sx?$|\.(vue|svelte|astro|py|rb|go|php|java|kt|rs)$/;
const JS_EXT = /\.(m|c)?(j|t)sx?$|\.(vue|svelte|astro)$/;
const TEST_PATH = /(^|\/)(__tests__|__mocks__|tests?|spec|fixtures?|e2e)\/|\.(test|spec)\.[a-z]+$/;

export const isCode = (f: SourceFile) => CODE_EXT.test(f.path);
export const isJs = (f: SourceFile) => JS_EXT.test(f.path);
export const isTest = (f: SourceFile) => TEST_PATH.test(f.path);

const SUPPRESS = /vibescan-ignore/;

export function isSuppressed(file: SourceFile, index: number): boolean {
  return SUPPRESS.test(file.lines[index] ?? "") || SUPPRESS.test(file.lines[index - 1] ?? "");
}

export function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  return t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*");
}

export function snippet(line: string): string {
  const t = line.trim();
  return t.length > 140 ? `${t.slice(0, 137)}...` : t;
}

/** Runs `test` on every non-comment line and returns a finding per match. */
export function scanLines(
  rule: Pick<Rule, "id" | "severity">,
  files: SourceFile[],
  test: (line: string, file: SourceFile, index: number) => string | false | undefined,
  opts: { includeComments?: boolean; mask?: (line: string) => string } = {},
): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    file.lines.forEach((line, i) => {
      if (!opts.includeComments && isCommentLine(line)) return;
      const message = test(line, file, i);
      if (!message || isSuppressed(file, i)) return;
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        message,
        file: file.path,
        line: i + 1,
        snippet: snippet(opts.mask ? opts.mask(line) : line),
      });
    });
  }
  return findings;
}

/**
 * Blanks regex literals (`/.../.test(x)`), so rules don't fire on code that
 * merely *describes* a pattern, like this scanner's own source.
 */
export function withoutRegexLiterals(line: string): string {
  return line.replace(/(^|[=(,:!&|?{;\s])\/(?![/*])(?:\\.|\[(?:\\.|[^\]])*\]|[^/\\\n[])+\/[dgimsuyv]*/g, "$1/regex/");
}

/** Also blanks the contents of string literals: for rules that look for *calls*. */
export function codeOnly(line: string): string {
  return withoutRegexLiterals(line).replace(/(["'`])(?:\\.|(?!\1).)*\1/g, "$1$1");
}
