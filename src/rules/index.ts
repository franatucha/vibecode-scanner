import type { Rule } from "../types.js";
import { hallucinatedDeps, llmInBrowser, missingRateLimit, noTests, openDatabaseRules } from "./project.js";
import { committedEnv, hardcodedSecrets, publicEnvSecret } from "./secrets.js";
import { corsWildcard, dangerousHtml, sqlInjection, unprotectedRoutes } from "./web.js";

export const rules: Rule[] = [
  hardcodedSecrets,
  committedEnv,
  publicEnvSecret,
  llmInBrowser,
  hallucinatedDeps,
  openDatabaseRules,
  sqlInjection,
  unprotectedRoutes,
  dangerousHtml,
  corsWildcard,
  missingRateLimit,
  noTests,
];

export const ruleById = new Map(rules.map((r) => [r.id, r]));
