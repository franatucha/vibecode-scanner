import type { Finding, Rule } from "../types.js";
import { codeOnly, isJs, isTest, scanLines, withoutRegexLiterals } from "./helpers.js";

export const llmInBrowser: Rule = {
  id: "ai/llm-in-browser",
  title: "LLM API called from the browser",
  severity: "critical",
  why: "Calling OpenAI/Anthropic from client code means shipping your API key to every visitor, who can then spend your credits.",
  fix: "Move the call to a server route and have the client call that route instead.",
  check({ project }) {
    return scanLines(this, project.files.filter((f) => isJs(f) && !isTest(f)), (raw, file) => {
      const line = withoutRegexLiterals(raw);
      if (/dangerouslyAllowBrowser\s*:\s*true/.test(codeOnly(raw))) return "`dangerouslyAllowBrowser: true` exposes the API key";
      const isClient = /^\s*['"]use client['"]/m.test(file.content);
      if (isClient && /new\s+(OpenAI|Anthropic)\s*\(|from\s+['"](openai|@anthropic-ai\/sdk)['"]/.test(line)) return "LLM SDK imported in a `'use client'` component";
      if (isClient && /fetch\(\s*['"`]https:\/\/api\.(openai|anthropic)\.com/.test(line)) return "LLM API fetched directly from a client component";
      return false;
    });
  },
};

export const openDatabaseRules: Rule = {
  id: "db/open-access",
  title: "Database open to everyone",
  severity: "critical",
  why: "Firebase rules that allow everything, or Supabase tables without row-level security, let anyone with your public key read and write all data.",
  fix: "Write rules scoped to `request.auth.uid`, and `alter table ... enable row level security` on every table with policies.",
  check({ project }) {
    const findings: Finding[] = [];
    const rulesFiles = project.files.filter((f) => /firestore\.rules$|storage\.rules$|database\.rules\.json$/.test(f.path));
    findings.push(
      ...scanLines(this, rulesFiles, (line) => {
        if (/allow\s+[\w, ]*:\s*if\s+true\s*;?/.test(line)) return "Firebase rule `allow ...: if true`";
        if (/['"]\.(read|write)['"]\s*:\s*(true|['"]true['"])/.test(line)) return "Realtime Database rule set to `true`";
        return false;
      }, { includeComments: false }),
    );

    // Supabase: every `create table` in migrations should have RLS enabled somewhere.
    const sqlFiles = project.files.filter((f) => f.path.endsWith(".sql") && /supabase/.test(f.path));
    if (sqlFiles.length) {
      const all = sqlFiles.map((f) => f.content).join("\n").toLowerCase();
      for (const f of sqlFiles) {
        f.lines.forEach((line, i) => {
          const m = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?(\w+)"?/i.exec(line);
          if (!m) return;
          const table = m[1]!.toLowerCase();
          const rls = new RegExp(`alter\\s+table\\s+(if\\s+exists\\s+)?("?public"?\\.)?"?${table}"?\\s+enable\\s+row\\s+level\\s+security`);
          if (!rls.test(all))
            findings.push({ ruleId: this.id, severity: this.severity, file: f.path, line: i + 1, snippet: line.trim(), message: `Table \`${table}\` has no row level security` });
        });
      }
    }
    return findings;
  },
};

const REGISTRY_TIMEOUT_MS = 4000;

async function exists(fetchFn: typeof fetch, url: string): Promise<boolean | undefined> {
  try {
    const res = await fetchFn(url, { method: "GET", headers: { accept: "application/json" }, signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS) });
    if (res.status === 404) return false;
    return res.ok ? true : undefined;
  } catch {
    return undefined; // offline or rate limited: don't guess
  }
}

export const hallucinatedDeps: Rule = {
  id: "deps/hallucinated",
  title: "Dependency that doesn't exist",
  severity: "critical",
  why: "LLMs invent plausible package names. Attackers register them ('slopsquatting'), so the next install runs their code.",
  fix: "Remove the dependency or replace it with the real package you meant. Never `npm install` a name you haven't checked.",
  async check({ project, online, fetch: fetchFn }) {
    if (!online) return [];
    const deps: { name: string; file: string; registry: "npm" | "pypi" }[] = [];
    for (const [file, pkg] of project.packageJsons) {
      for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
        if (/^(workspace:|file:|link:|git|https?:|github:|npm:)/.test(version)) continue;
        deps.push({ name, file, registry: "npm" });
      }
    }
    for (const f of project.files.filter((f) => /(^|\/)requirements[\w-]*\.txt$/.test(f.path))) {
      for (const line of f.lines) {
        const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line);
        if (m && !line.trim().startsWith("-")) deps.push({ name: m[1]!, file: f.path, registry: "pypi" });
      }
    }

    const unique = [...new Map(deps.map((d) => [`${d.registry}:${d.name}`, d])).values()];
    const results: Finding[] = [];
    const CONCURRENCY = 8;
    for (let i = 0; i < unique.length; i += CONCURRENCY) {
      await Promise.all(
        unique.slice(i, i + CONCURRENCY).map(async (d) => {
          const url = d.registry === "npm" ? `https://registry.npmjs.org/${d.name.replace("/", "%2F")}` : `https://pypi.org/pypi/${d.name}/json`;
          if ((await exists(fetchFn, url)) === false)
            results.push({ ruleId: this.id, severity: this.severity, file: d.file, message: `\`${d.name}\` is not on ${d.registry === "npm" ? "npm" : "PyPI"}` });
        }),
      );
    }
    return results;
  },
};

export const missingRateLimit: Rule = {
  id: "abuse/no-rate-limit",
  title: "No rate limiting on expensive endpoints",
  severity: "medium",
  why: "Endpoints that call an LLM or send email cost money per request. Without a limit, one script can run up your bill overnight.",
  fix: "Add a per-user or per-IP limit (e.g. @upstash/ratelimit, express-rate-limit) in front of LLM, email and auth routes.",
  check({ project }) {
    const code = project.files.filter((f) => isJs(f) && !isTest(f));
    const hasLimiter = code.some((f) => /rate.?limit|ratelimit|limiter|throttle|slowDown/i.test(f.content)) ||
      [...project.packageJsons.values()].some((p) => Object.keys({ ...p.dependencies }).some((d) => /rate-?limit|limiter|throttle/.test(d)));
    if (hasLimiter) return [];
    const expensive = code.find((f) => /(route\.(t|j)s|pages\/api\/|server|api\/)/.test(f.path) && /(openai|anthropic|chat\.completions|messages\.create|resend|sendgrid|nodemailer|twilio)/i.test(f.content));
    if (!expensive) return [];
    return [{ ruleId: this.id, severity: this.severity, file: expensive.path, message: `\`${expensive.path}\` calls a paid API and the project has no rate limiter` }];
  },
};

export const noTests: Rule = {
  id: "quality/no-tests",
  title: "No tests",
  severity: "low",
  why: "Without tests, every 'small fix' an AI makes can silently break something that used to work.",
  fix: "Start with one test per critical flow (sign-in, checkout, the core calculation) and run them in CI.",
  check({ project }) {
    const hasTestFiles = project.files.some(isTest);
    const hasTestScript = [...project.packageJsons.values()].some((p) => p.scripts?.test && !/no test specified/.test(p.scripts.test));
    const hasCode = project.files.some((f) => isJs(f) || f.path.endsWith(".py"));
    if (!hasCode || hasTestFiles || hasTestScript) return [];
    return [{ ruleId: this.id, severity: this.severity, message: "No test files and no `test` script found" }];
  },
};
