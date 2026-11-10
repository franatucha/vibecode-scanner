import type { Finding, Rule } from "../types.js";
import { isCode, isTest, scanLines } from "./helpers.js";

interface SecretPattern {
  name: string;
  re: RegExp;
}

// Provider-specific formats: precise enough to report as critical.
const PATTERNS: SecretPattern[] = [
  { name: "Anthropic API key", re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: "OpenAI API key", re: /sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/ },
  { name: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Resend API key", re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}\b/ },
  { name: "private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: "database URL with password", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s'"]+:[^@\s'"]{4,}@(?!localhost|127\.0\.0\.1)/ },
  { name: "Supabase service role key", re: /service_role['"]?\s*[:=]\s*['"]eyJ[A-Za-z0-9_-]{20,}/ },
];

// Generic `secret = "..."` assignments: noisier, so reported as high.
const GENERIC = /\b([A-Za-z_]*(?:api[_-]?key|secret|passw(?:or)?d|auth[_-]?token|access[_-]?token|private[_-]?key))['"]?\s*[:=]\s*['"`]([^'"`\s]{12,})['"`]/i;
const PLACEHOLDER = /^(?:x+|\*+|your|change|replace|example|placeholder|dummy|test|fake|todo|<|\$\{|process\.env|xxx)/i;

export function mask(line: string): string {
  // Database URLs: keep the host visible, hide only the password.
  let out = line.replace(/(:\/\/[^:\s'"]+:)([^@\s'"]{4,})@/g, (_m, pre: string) => `${pre}${"•".repeat(8)}@`);
  for (const { name, re } of PATTERNS) {
    if (name.startsWith("database")) continue;
    out = out.replace(new RegExp(re.source, "g"), (m) => `${m.slice(0, 6)}${"•".repeat(8)}`);
  }
  return out.replace(new RegExp(GENERIC.source, "gi"), (m, _k, value: string) => m.replace(value, `${value.slice(0, 3)}${"•".repeat(8)}`));
}

export const hardcodedSecrets: Rule = {
  id: "secrets/hardcoded",
  title: "Hardcoded secret",
  severity: "critical",
  why: "Anything committed is public forever once the repo is pushed: bots scrape GitHub for keys within minutes.",
  fix: "Move it to an environment variable, then rotate the key: removing it from the code doesn't un-leak it.",
  check({ project }) {
    const files = project.files.filter(
      (f) => (isCode(f) || /\.(json|ya?ml|toml|html)$/.test(f.path)) && !isTest(f) && !/\.example$|\.sample$/.test(f.path),
    );
    const precise = scanLines(this, files, (line) => PATTERNS.find((p) => p.re.test(line))?.name.replace(/^/, "Hardcoded ") ?? false, { includeComments: true, mask });
    const seen = new Set(precise.map((f) => `${f.file}:${f.line}`));
    const generic = scanLines({ ...this, severity: "high" }, files, (line, file, i) => {
      if (seen.has(`${file.path}:${i + 1}`)) return false;
      const m = GENERIC.exec(line);
      if (!m || PLACEHOLDER.test(m[2]!)) return false;
      return `Possible hardcoded credential in \`${m[1]}\``;
    }, { mask });
    return [...precise, ...generic];
  },
};

export const committedEnv: Rule = {
  id: "secrets/env-committed",
  title: ".env file committed",
  severity: "critical",
  why: "A committed .env file publishes every key in it, and it stays in git history even after you delete it.",
  fix: "Add `.env*` (with `!.env.example`) to .gitignore, run `git rm --cached .env`, and rotate every key it held.",
  check({ project }) {
    const findings: Finding[] = [];
    for (const f of project.files) {
      const name = f.path.split("/").pop()!;
      if (!(name === ".env" || name.startsWith(".env.")) || /example|sample|template|defaults/.test(name)) continue;
      const hasValues = f.lines.some((l) => /^\s*[A-Z0-9_]+\s*=\s*\S+/.test(l));
      if (!hasValues) continue;
      // In a git repo only tracked files are a leak; outside git we can't tell, so flag it.
      if (project.tracked) {
        if (!project.tracked.has(f.path)) continue;
        findings.push({ ruleId: this.id, severity: this.severity, file: f.path, message: `\`${f.path}\` is tracked by git` });
      } else {
        findings.push({ ruleId: this.id, severity: "high", file: f.path, message: `\`${f.path}\` exists; make sure it is git-ignored` });
      }
    }
    return findings;
  },
};

const PUBLIC_PREFIX = /\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)([A-Z0-9_]+)/;
const SENSITIVE = /SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|SERVICE_KEY|OPENAI|ANTHROPIC|STRIPE_SECRET|STRIPE_SK|DATABASE_URL|ADMIN_KEY|RESEND|SENDGRID|TWILIO_AUTH/;

export const publicEnvSecret: Rule = {
  id: "secrets/public-env",
  title: "Secret exposed through a public env var",
  severity: "critical",
  why: "Variables prefixed NEXT_PUBLIC_, VITE_ and similar are inlined into the JavaScript bundle that every visitor downloads.",
  fix: "Drop the public prefix and only read the value in server code (API routes, server actions, route handlers).",
  check({ project }) {
    const seen = new Set<string>();
    return scanLines(this, project.files.filter((f) => !isTest(f)), (line) => {
      const m = PUBLIC_PREFIX.exec(line);
      if (!m || !SENSITIVE.test(m[2]!)) return false;
      const name = m[1]! + m[2]!;
      if (seen.has(name)) return false;
      seen.add(name);
      return `\`${name}\` ships to the browser`;
    }, { mask });
  },
};
