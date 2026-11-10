export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export interface SourceFile {
  /** Path relative to the scan root, always with forward slashes. */
  path: string;
  content: string;
  lines: string[];
}

export interface Project {
  root: string;
  files: SourceFile[];
  /** Parsed package.json files, keyed by their relative path. */
  packageJsons: Map<string, PackageJson>;
  /** Set when the scan root is a git repository. */
  tracked?: Set<string>;
}

export interface PackageJson {
  name?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  /** The offending line, with secrets masked. */
  snippet?: string;
}

export interface RuleContext {
  project: Project;
  online: boolean;
  fetch: typeof globalThis.fetch;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  /** One sentence: why this matters. Shown in reports. */
  why: string;
  /** One sentence: how to fix it. */
  fix: string;
  check(ctx: RuleContext): Finding[] | Promise<Finding[]>;
}

export interface ScanResult {
  root: string;
  filesScanned: number;
  findings: Finding[];
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  durationMs: number;
  online: boolean;
}
