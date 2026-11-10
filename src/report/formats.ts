import { rules, ruleById } from "../rules/index.js";
import type { ScanResult, Severity } from "../types.js";

export function jsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

const EMOJI: Record<Severity, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "⚪" };

/** For GitHub step summaries and PR comments. */
export function markdownReport(result: ScanResult): string {
  const lines = [
    `## vibescan: ${result.score}/100 (grade ${result.grade})`,
    "",
    `Scanned ${result.filesScanned} files in ${result.durationMs}ms.`,
    "",
  ];
  if (!result.findings.length) return [...lines, "✅ No issues found."].join("\n");
  lines.push("| | Issue | Where |", "|---|---|---|");
  for (const f of result.findings) {
    const where = f.file ? `\`${f.file}${f.line ? `:${f.line}` : ""}\`` : "";
    lines.push(`| ${EMOJI[f.severity]} | **${ruleById.get(f.ruleId)?.title ?? f.ruleId}**: ${f.message.replace(/\|/g, "\\|")} | ${where} |`);
  }
  lines.push("", "<details><summary>How to fix</summary>", "");
  for (const id of new Set(result.findings.map((f) => f.ruleId))) {
    const r = ruleById.get(id);
    if (r) lines.push(`- **${r.title}**: ${r.fix}`);
  }
  lines.push("", "</details>");
  return lines.join("\n");
}

const SARIF_LEVEL: Record<Severity, string> = { critical: "error", high: "error", medium: "warning", low: "note" };
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "7.5", medium: "5.0", low: "2.0" };

/** SARIF 2.1.0, so findings show up in GitHub's code scanning tab. */
export function sarifReport(result: ScanResult): string {
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "vibescan",
              informationUri: "https://github.com/franatucha/vibecode-scanner",
              rules: rules.map((r) => ({
                id: r.id,
                name: r.title,
                shortDescription: { text: r.title },
                fullDescription: { text: r.why },
                help: { text: r.fix, markdown: `**Why:** ${r.why}\n\n**Fix:** ${r.fix}` },
                defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
                properties: { "security-severity": SECURITY_SEVERITY[r.severity], tags: ["security"] },
              })),
            },
          },
          results: result.findings.map((f) => ({
            ruleId: f.ruleId,
            level: SARIF_LEVEL[f.severity],
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file ?? "." },
                  ...(f.line ? { region: { startLine: f.line } } : {}),
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}
