import { resolve } from "node:path";
import { loadProject } from "./project.js";
import { rules as allRules } from "./rules/index.js";
import { SEVERITY_ORDER } from "./types.js";
const WEIGHT = { critical: 25, high: 12, medium: 5, low: 2 };
/**
 * 100 minus a penalty per rule. Repeats of the same rule count less each time,
 * capped at twice the base weight, so one noisy rule can't zero the score alone.
 */
export function computeScore(findings) {
    const byRule = new Map();
    for (const f of findings)
        byRule.set(f.ruleId, [...(byRule.get(f.ruleId) ?? []), f]);
    let penalty = 0;
    for (const group of byRule.values()) {
        const worst = SEVERITY_ORDER.find((s) => group.some((f) => f.severity === s));
        const base = WEIGHT[worst];
        penalty += Math.min(base * 2, base * (1 + 0.5 * (group.length - 1)));
    }
    const score = Math.max(0, Math.round(100 - penalty));
    const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
    return { score, grade };
}
const ruleOrder = (id) => {
    const i = allRules.findIndex((r) => r.id === id);
    return i === -1 ? allRules.length : i;
};
export function sortFindings(findings) {
    return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        ruleOrder(a.ruleId) - ruleOrder(b.ruleId) ||
        (a.file ?? "").localeCompare(b.file ?? "") ||
        (a.line ?? 0) - (b.line ?? 0));
}
export async function scan(dir, opts = {}) {
    const started = performance.now();
    const root = resolve(dir);
    const project = loadProject(root, { ignore: opts.ignore });
    const disabled = new Set(opts.disable ?? []);
    const active = (opts.rules ?? allRules).filter((r) => !disabled.has(r.id));
    const ctx = { project, online: opts.online ?? false, fetch: opts.fetch ?? globalThis.fetch };
    const findings = (await Promise.all(active.map((r) => r.check(ctx)))).flat();
    const sorted = sortFindings(findings);
    return {
        root,
        filesScanned: project.files.length,
        findings: sorted,
        ...computeScore(sorted),
        durationMs: Math.round(performance.now() - started),
        online: ctx.online,
    };
}
