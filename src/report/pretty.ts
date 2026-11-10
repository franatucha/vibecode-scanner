import { ruleById } from "../rules/index.js";
import { SEVERITY_ORDER, type Finding, type ScanResult, type Severity } from "../types.js";

export function colors(enabled: boolean) {
  const wrap = (open: number, close: number) => (s: string) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : s);
  return {
    bold: wrap(1, 22), dim: wrap(2, 22), red: wrap(31, 39), green: wrap(32, 39),
    yellow: wrap(33, 39), blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39),
    bgRed: wrap(41, 49), bgYellow: wrap(43, 49), bgGreen: wrap(42, 49),
  };
}

/** Wraps `text` to `width`, indenting continuation lines by `indent` spaces. */
export function wrap(text: string, width: number, indent: number): string {
  const max = Math.max(30, width - indent);
  const lines: string[] = [];
  let current = "";
  for (const word of text.split(" ")) {
    if (current && current.length + 1 + word.length > max) {
      lines.push(current);
      current = word;
    } else current = current ? `${current} ${word}` : word;
  }
  if (current) lines.push(current);
  return lines.join(`\n${" ".repeat(indent)}`);
}

const truncate = (s: string, max: number) => (s.length > max ? `${s.slice(0, max - 3)}...` : s);

export function prettyReport(result: ScanResult, useColor: boolean, width = 100): string {
  const c = colors(useColor);
  const sevStyle: Record<Severity, (s: string) => string> = {
    critical: (s) => c.bold(c.red(s)), high: c.red, medium: c.yellow, low: c.dim,
  };
  const gradeColor = { A: c.green, B: c.green, C: c.yellow, D: c.red, F: c.red }[result.grade];
  const out: string[] = [];

  out.push("", `  ${c.bold("vibescan")} ${c.dim(`· ${result.filesScanned} files · ${result.durationMs}ms${result.online ? "" : " · offline"}`)}`, "");

  // Group by rule so each explanation prints once.
  const groups = new Map<string, Finding[]>();
  for (const f of result.findings) groups.set(f.ruleId, [...(groups.get(f.ruleId) ?? []), f]);

  for (const [ruleId, findings] of groups) {
    const rule = ruleById.get(ruleId);
    const sev = findings[0]!.severity;
    out.push(`  ${sevStyle[sev](sev.toUpperCase().padEnd(8))} ${c.bold(rule?.title ?? ruleId)} ${c.dim(`(${findings.length})`)}`);
    for (const f of findings.slice(0, 8)) {
      const loc = f.file ? c.cyan(`${f.file}${f.line ? `:${f.line}` : ""}`) : "";
      out.push(`           ${loc}${loc ? "  " : ""}${f.message}`);
      if (f.snippet) out.push(`           ${c.dim("│")} ${c.dim(truncate(f.snippet, width - 13))}`);
    }
    if (findings.length > 8) out.push(c.dim(`           ...and ${findings.length - 8} more`));
    if (rule) out.push(`           ${c.dim("why")}  ${wrap(rule.why, width, 16)}`, `           ${c.green("fix")}  ${wrap(rule.fix, width, 16)}`);
    out.push("");
  }

  if (!result.findings.length) out.push(`  ${c.green("✓")} No issues found.`, "");

  const counts = SEVERITY_ORDER.map((s) => [s, result.findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => sevStyle[s](`${n} ${s}`));
  const bar = (() => {
    const filled = Math.round(result.score / 5);
    return gradeColor("█".repeat(filled)) + c.dim("░".repeat(20 - filled));
  })();
  out.push(`  ${c.bold("Score")}  ${bar}  ${c.bold(gradeColor(`${result.score}/100`))}  ${c.bold(gradeColor(`grade ${result.grade}`))}`);
  if (counts.length) out.push(`         ${counts.join(c.dim(" · "))}`);
  if (!result.online) out.push(c.dim("         Run with --online to also check for hallucinated packages."));
  out.push("");
  return out.join("\n");
}
