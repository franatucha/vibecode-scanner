#!/usr/bin/env node
import { existsSync, statSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { jsonReport, markdownReport, sarifReport } from "./report/formats.js";
import { prettyReport } from "./report/pretty.js";
import { rules } from "./rules/index.js";
import { scan } from "./scan.js";
import { SEVERITY_ORDER, type Severity } from "./types.js";

const HELP = `
vibescan - audit AI-generated code for the mistakes vibe coding leaves behind

Usage
  vibescan [dir] [options]

Options
  --online              Also check that every dependency exists on npm / PyPI
  --format <f>          pretty (default) | json | markdown | sarif
  --output, -o <file>   Write the report to a file instead of stdout
  --fail-on <sev>       Exit 1 if any finding is at least this severe: critical | high | medium | low
  --min-score <n>       Exit 1 if the score is below n
  --ignore <glob>       Skip matching paths (repeatable)
  --disable <rule>      Skip a rule by id (repeatable)
  --list-rules          Print every rule and exit
  --no-color            Disable colors
  -h, --help            Show this help

Silence a single line with a  // vibescan-ignore  comment on it or the line above.
Skip paths for good by listing globs in a .vibescanignore file at the scan root.
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      online: { type: "boolean", default: false },
      format: { type: "string", default: "pretty" },
      output: { type: "string", short: "o" },
      "fail-on": { type: "string" },
      "min-score": { type: "string" },
      ignore: { type: "string", multiple: true },
      disable: { type: "string", multiple: true },
      "list-rules": { type: "boolean", default: false },
      "no-color": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (values["list-rules"]) {
    for (const r of rules) process.stdout.write(`${r.severity.padEnd(9)}${r.id.padEnd(26)}${r.title}\n`);
    return 0;
  }

  const dir = positionals[0] ?? ".";
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    process.stderr.write(`vibescan: ${dir} is not a directory\n`);
    return 2;
  }
  const failOn = values["fail-on"] as Severity | undefined;
  if (failOn && !SEVERITY_ORDER.includes(failOn)) {
    process.stderr.write(`vibescan: --fail-on must be one of ${SEVERITY_ORDER.join(", ")}\n`);
    return 2;
  }

  const result = await scan(dir, { online: values.online, ignore: values.ignore, disable: values.disable });

  const useColor = !values["no-color"] && !values.output && !process.env.NO_COLOR && (process.stdout.isTTY || Boolean(process.env.FORCE_COLOR));
  const report =
    values.format === "json" ? jsonReport(result)
    : values.format === "sarif" ? sarifReport(result)
    : values.format === "markdown" ? markdownReport(result)
    : prettyReport(result, Boolean(useColor), Math.min(Number(process.env.COLUMNS) || process.stdout.columns || 100, 120));

  if (values.output) writeFileSync(values.output, report + "\n");
  else process.stdout.write(report + "\n");

  if (failOn) {
    const threshold = SEVERITY_ORDER.indexOf(failOn);
    if (result.findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= threshold)) return 1;
  }
  if (values["min-score"] && result.score < Number(values["min-score"])) return 1;
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err: unknown) => {
    process.stderr.write(`vibescan: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  },
);
