import type { Finding, Rule, SourceFile } from "../types.js";
import { codeOnly, isJs, isSuppressed, isTest, scanLines, snippet, withoutRegexLiterals } from "./helpers.js";

const AUTH_HINTS =
  /\b(auth|getServerSession|getSession|currentUser|requireUser|requireAuth|requireAdmin|withAuth|verifyToken|jwt\.verify|jwtVerify|clerk|getAuth|supabase\.auth\.getUser|session|isAuthenticated|authorize|ensureUser|getUser|cookies\(\)\.get|headers\(\)\.get\(['"]authorization|x-api-key|bearer|signature|webhook|svix|stripe\.webhooks)/i;

const MUTATING_EXPORT = /export\s+(?:async\s+)?(?:function\s+|const\s+)(POST|PUT|PATCH|DELETE)\b/;

/** Does a middleware file protect API routes? Then route-level checks are optional. */
function middlewareProtectsApi(files: SourceFile[]): boolean {
  return files.some((f) => /(^|\/)(src\/)?middleware\.(t|j)s$/.test(f.path) && AUTH_HINTS.test(f.content) && /api|matcher/.test(f.content));
}

export const unprotectedRoutes: Rule = {
  id: "auth/unprotected-route",
  title: "API route without an auth check",
  severity: "high",
  why: "A route that writes data but never checks who's calling lets anyone on the internet do it, usually with a single curl.",
  fix: "Check the session (or an API key / webhook signature) at the top of the handler and return 401 before doing anything.",
  check({ project }) {
    const files = project.files.filter((f) => isJs(f) && !isTest(f));
    if (middlewareProtectsApi(files)) return [];
    const findings: Finding[] = [];

    for (const f of files) {
      // Next.js App Router: app/**/route.ts exporting POST/PUT/PATCH/DELETE
      if (/(^|\/)app\/.*\/route\.(t|j)sx?$/.test(f.path)) {
        if (AUTH_HINTS.test(f.content)) continue;
        f.lines.forEach((line, i) => {
          const m = MUTATING_EXPORT.exec(line);
          if (m && !isSuppressed(f, i))
            findings.push({ ruleId: this.id, severity: this.severity, file: f.path, line: i + 1, snippet: snippet(line), message: `\`${m[1]}\` handler never checks who is calling` });
        });
        continue;
      }
      // Next.js Pages Router: pages/api/**
      if (/(^|\/)pages\/api\//.test(f.path)) {
        const idx = f.lines.findIndex((l) => /export\s+default/.test(l));
        if (idx !== -1 && !AUTH_HINTS.test(f.content) && /req\.method|POST|body/.test(f.content) && !isSuppressed(f, idx))
          findings.push({ ruleId: this.id, severity: this.severity, file: f.path, line: idx + 1, snippet: snippet(f.lines[idx]!), message: "API handler never checks who is calling" });
        continue;
      }
      // Express / Fastify / Hono style: router.post("/x", async (req, res) => ...)
      if (/\b(express|fastify|hono|koa)\b/.test(f.content) && !/\.use\([^)]*auth/i.test(f.content)) {
        findings.push(
          ...scanLines(this, [f], (line) => {
            const m = /\b(?:app|router|server)\.(post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]\s*,\s*(async\s*)?\(/.exec(line);
            if (!m || /webhook|login|signup|register|health/.test(m[2]!)) return false;
            return `\`${m[1]!.toUpperCase()} ${m[2]}\` has no auth middleware`;
          }),
        );
      }
    }
    return findings;
  },
};

export const sqlInjection: Rule = {
  id: "injection/sql",
  title: "SQL built from strings",
  severity: "critical",
  why: "Interpolating user input into SQL lets an attacker rewrite the query: read every table, or drop them.",
  fix: "Use parameters ($1, ?) or a tagged template your driver escapes (sql`...`, prisma.$queryRaw`...`).",
  check({ project }) {
    const SQL = /\b(SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i;
    return scanLines(this, project.files.filter((f) => isJs(f) || f.path.endsWith(".py")), (line) => {
      if (/\$(queryRaw|executeRaw)Unsafe\s*\(/.test(line)) return "`$queryRawUnsafe` with a dynamic string";
      if (/\bsql\.raw\s*\(\s*`[^`]*\$\{/.test(line)) return "`sql.raw()` with interpolated input";
      if (!SQL.test(line)) return false;
      // Tagged templates (sql`...`, Prisma.sql`...`) are escaped by the driver: safe.
      if (/\b(sql|Prisma\.sql|\$queryRaw|\$executeRaw)\s*`/.test(line)) return false;
      if (/`[^`]*\$\{[^}]+\}[^`]*`/.test(line)) return "SQL query built with a template literal";
      if (/['"][^'"]*['"]\s*\+\s*[\w.[\]]+/.test(line)) return "SQL query built with string concatenation";
      if (/\bf['"][^'"]*\{[^}]+\}/.test(line) || /%\s*\(?\s*\w+/.test(line) && /execute\(/.test(line)) return "SQL query built with string formatting";
      return false;
    });
  },
};

export const corsWildcard: Rule = {
  id: "web/cors-wildcard",
  title: "CORS open to every origin",
  severity: "medium",
  why: "`*` (or reflecting any origin) lets any website call your API from a visitor's browser; with credentials it can act as them.",
  fix: "List the origins you actually serve: `cors({ origin: ['https://yourapp.com'] })`.",
  check({ project }) {
    return scanLines(this, project.files.filter((f) => isJs(f) || f.path.endsWith(".py") || /vercel\.json|next\.config/.test(f.path)), (raw) => {
      const line = withoutRegexLiterals(raw);
      if (/Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/i.test(line)) return "`Access-Control-Allow-Origin: *`";
      if (/\borigin\s*:\s*(['"]\*['"]|true)\b/.test(line)) return "CORS `origin` accepts any site";
      if (/\bcors\(\s*\)/.test(codeOnly(raw))) return "`cors()` with default options allows every origin";
      if (/allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]/.test(line.replace(/`[^`]*`/g, "``"))) return "`allow_origins=['*']`";
      return false;
    });
  },
};

export const dangerousHtml: Rule = {
  id: "injection/xss",
  title: "Unsanitized HTML or eval",
  severity: "high",
  why: "Rendering raw HTML or evaluating strings runs whatever an attacker manages to store, inside your users' sessions.",
  fix: "Render text instead, or sanitize with DOMPurify first. Never pass user data to eval / new Function.",
  check({ project }) {
    return scanLines(this, project.files.filter((f) => isJs(f) && !isTest(f)), (raw, file, i) => {
      const line = codeOnly(raw);
      // <style dangerouslySetInnerHTML> with generated CSS (e.g. shadcn's chart) and JSON-LD are fine.
      const context = file.lines.slice(Math.max(0, i - 2), i + 1).join(" ");
      if (/dangerouslySetInnerHTML/.test(line) && /<style|application\/ld\+json|JSON\.stringify/.test(context)) return false;
      if (/dangerouslySetInnerHTML/.test(line) && !/(DOMPurify|sanitize|purify|xss)/i.test(file.content)) return "`dangerouslySetInnerHTML` without sanitizing";
      if (/\.innerHTML\s*=\s*(?!['"`]\s*['"`])/.test(line) && !/(DOMPurify|sanitize)/i.test(file.content)) return "Assigning to `innerHTML`";
      if (/(^|[^\w.])eval\s*\(/.test(line)) return "`eval()`";
      if (/new\s+Function\s*\(/.test(line)) return "`new Function()`";
      return false;
    });
  },
};
