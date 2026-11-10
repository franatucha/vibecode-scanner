import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { sarifReport, markdownReport } from "../src/report/formats.js";
import { codeOnly, withoutRegexLiterals } from "../src/rules/helpers.js";
import { rules } from "../src/rules/index.js";
import { mask } from "../src/rules/secrets.js";
import { computeScore, scan } from "../src/scan.js";
import type { Finding, ScanResult } from "../src/types.js";

const VIBE = join(__dirname, "../examples/vibe-app");
const CLEAN = join(__dirname, "fixtures/clean-app");

/** Pretends every package exists except the ones listed. */
const fakeRegistry = (missing: string[]) =>
  (async (url: string | URL | Request) => {
    const name = decodeURIComponent(String(url).split("/").pop()!);
    return new Response("{}", { status: missing.includes(name) ? 404 : 200 });
  }) as typeof fetch;

describe("vibe-app (deliberately broken)", () => {
  let result: ScanResult;
  const ids = () => new Set(result.findings.map((f) => f.ruleId));
  const at = (ruleId: string) => result.findings.filter((f) => f.ruleId === ruleId);

  beforeAll(async () => {
    result = await scan(VIBE, { online: true, fetch: fakeRegistry(["next-supabase-easy-auth", "openai-stream-helpers-pro"]) });
  });

  it("triggers every rule", () => {
    for (const rule of rules) expect(ids(), rule.id).toContain(rule.id);
  });

  it("finds both SQL injections, and nothing else as SQL", () => {
    expect(at("injection/sql").map((f) => f.line)).toEqual([4, 9]);
  });

  it("flags only the mutating handlers without auth", () => {
    expect(at("auth/unprotected-route").map((f) => `${f.file}:${f.line}`)).toEqual([
      "app/api/chat/route.ts:5",
      "app/api/users/[id]/route.ts:8",
      "server.ts:8",
    ]);
  });

  it("names the hallucinated packages and nothing real", () => {
    expect(at("deps/hallucinated").map((f) => f.message)).toEqual([
      "`next-supabase-easy-auth` is not on npm",
      "`openai-stream-helpers-pro` is not on npm",
    ]);
  });

  it("finds the Supabase table without RLS, not the one with it", () => {
    const sb = at("db/open-access").filter((f) => f.file?.endsWith(".sql"));
    expect(sb.map((f) => f.message)).toEqual(["Table `profiles` has no row level security"]);
  });

  it("never prints a secret in full", () => {
    const all = JSON.stringify(result.findings);
    expect(all).not.toContain("SuperSecret123");
    expect(all).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("grades it F", () => {
    expect(result.grade).toBe("F");
  });
});

describe("clean-app", () => {
  it("has no findings and scores 100", async () => {
    const result = await scan(CLEAN, { online: true, fetch: fakeRegistry([]) });
    expect(result.findings).toEqual([]);
    expect(result.score).toBe(100);
  });
});

describe("hallucinated deps", () => {
  it("is skipped offline", async () => {
    const result = await scan(VIBE, { online: false });
    expect(result.findings.some((f) => f.ruleId === "deps/hallucinated")).toBe(false);
  });

  it("doesn't guess when the registry is unreachable", async () => {
    const down = (async () => { throw new Error("offline"); }) as typeof fetch;
    const result = await scan(VIBE, { online: true, fetch: down });
    expect(result.findings.some((f) => f.ruleId === "deps/hallucinated")).toBe(false);
  });
});

describe("options", () => {
  it("--disable skips a rule", async () => {
    const result = await scan(VIBE, { disable: ["injection/sql"] });
    expect(result.findings.some((f) => f.ruleId === "injection/sql")).toBe(false);
  });

  it("--ignore skips paths", async () => {
    const result = await scan(VIBE, { ignore: ["app/**"] });
    expect(result.findings.some((f) => f.file?.startsWith("app/"))).toBe(false);
  });
});

describe("outside a git repo", () => {
  it("still warns about a .env file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vibescan-"));
    writeFileSync(join(dir, ".env"), "OPENAI_API_KEY=abc123\n");
    const result = await scan(dir);
    expect(result.findings).toMatchObject([{ ruleId: "secrets/env-committed", severity: "high" }]);
  });
});

describe("scoring", () => {
  const f = (ruleId: string, severity: Finding["severity"]): Finding => ({ ruleId, severity, message: "" });

  it("starts at 100", () => expect(computeScore([])).toEqual({ score: 100, grade: "A" }));

  it("penalises repeats less, and caps them", () => {
    expect(computeScore([f("a", "high")]).score).toBe(88);
    expect(computeScore([f("a", "high"), f("a", "high")]).score).toBe(82);
    expect(computeScore(Array.from({ length: 50 }, () => f("a", "high"))).score).toBe(76);
  });

  it("never goes below 0", () => {
    expect(computeScore(["a", "b", "c", "d", "e"].map((id) => f(id, "critical"))).score).toBe(0);
  });
});

describe("helpers", () => {
  it("masks secrets but keeps context", () => {
    expect(mask('url = "postgres://admin:hunter2pass@db.example.com/x"')).toBe('url = "postgres://admin:••••••••@db.example.com/x"');
    expect(mask('const k = "AKIAIOSFODNN7EXAMPLE"')).toBe('const k = "AKIAIO••••••••"');
  });

  it("ignores patterns inside regex and string literals", () => {
    expect(withoutRegexLiterals("if (/eval\\(/.test(line)) x()")).toBe("if (/regex/.test(line)) x()");
    expect(codeOnly('msg("call eval() here")')).toBe('msg("")');
  });
});

describe("reports", () => {
  it("produces SARIF GitHub can ingest", async () => {
    const sarif = JSON.parse(sarifReport(await scan(VIBE)));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(rules.length);
    expect(sarif.runs[0].results[0]).toMatchObject({ ruleId: expect.any(String), level: "error" });
  });

  it("produces a markdown summary", async () => {
    expect(markdownReport(await scan(VIBE))).toMatch(/^## vibescan: \d+\/100 \(grade F\)/);
  });
});

describe("cli", () => {
  const cli = join(__dirname, "../dist/cli.js");
  beforeAll(() => execFileSync("npx", ["tsc", "-p", join(__dirname, "../tsconfig.json")]));
  const run = (...args: string[]) => spawnSync("node", [cli, ...args], { encoding: "utf8" });

  it("exits 0 by default, 1 with --fail-on", () => {
    expect(run(VIBE).status).toBe(0);
    expect(run(VIBE, "--fail-on", "critical").status).toBe(1);
    expect(run(CLEAN, "--fail-on", "low").status).toBe(0);
  });

  it("exits 1 below --min-score", () => {
    expect(run(VIBE, "--min-score", "50").status).toBe(1);
    expect(run(CLEAN, "--min-score", "100").status).toBe(0);
  });

  it("rejects bad input with exit 2", () => {
    expect(run("/does/not/exist").status).toBe(2);
    expect(run(VIBE, "--fail-on", "nope").status).toBe(2);
  });

  it("emits valid JSON", () => {
    expect(JSON.parse(run(VIBE, "--format", "json").stdout).grade).toBe("F");
  });
});
