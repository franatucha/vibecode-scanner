import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
const IGNORED_DIRS = new Set([
    "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    ".vercel", ".turbo", "coverage", "vendor", "__pycache__", ".venv", "venv", ".cache",
]);
const TEXT_EXTENSIONS = new Set([
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro",
    ".py", ".rb", ".go", ".php", ".java", ".kt", ".rs",
    ".json", ".yml", ".yaml", ".toml", ".sql", ".rules", ".html", ".txt", ".md", ".sh",
]);
const LOCKFILES = new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "poetry.lock"]);
const MAX_FILE_BYTES = 1_000_000;
function isEnvFile(name) {
    return name === ".env" || name.startsWith(".env.");
}
function shouldRead(relPath) {
    const name = relPath.split("/").pop() ?? relPath;
    if (LOCKFILES.has(name))
        return false;
    if (name.endsWith(".min.js"))
        return false;
    if (isEnvFile(name))
        return true;
    if (name === "Dockerfile" || name === "firestore.rules" || name === "database.rules.json")
        return true;
    const dot = name.lastIndexOf(".");
    return dot !== -1 && TEXT_EXTENSIONS.has(name.slice(dot));
}
function gitFiles(root) {
    try {
        const run = (args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 })
            .split("\0")
            .filter(Boolean);
        const tracked = run(["ls-files", "-z", "--cached"]);
        const untracked = run(["ls-files", "-z", "--others", "--exclude-standard"]);
        return { all: [...new Set([...tracked, ...untracked])], tracked: new Set(tracked) };
    }
    catch {
        return undefined;
    }
}
function walk(root, dir = root, out = []) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
            if (!IGNORED_DIRS.has(entry.name))
                walk(root, join(dir, entry.name), out);
        }
        else if (entry.isFile()) {
            out.push(relative(root, join(dir, entry.name)).split(sep).join("/"));
        }
    }
    return out;
}
export function loadProject(root, opts = {}) {
    const git = gitFiles(root);
    const ignore = [...readIgnoreFile(root), ...(opts.ignore ?? [])].map(globToRegExp);
    const paths = (git?.all ?? walk(root)).filter((p) => !p.split("/").some((part) => IGNORED_DIRS.has(part)) && shouldRead(p) && !ignore.some((re) => re.test(p)));
    const files = [];
    const packageJsons = new Map();
    for (const path of paths.sort()) {
        const abs = join(root, path);
        let content;
        try {
            if (statSync(abs).size > MAX_FILE_BYTES)
                continue;
            content = readFileSync(abs, "utf8");
        }
        catch {
            continue; // deleted from the working tree, or unreadable
        }
        if (content.includes("\u0000"))
            continue; // binary
        files.push({ path, content, lines: content.split(/\r?\n/) });
        if (path === "package.json" || path.endsWith("/package.json")) {
            try {
                packageJsons.set(path, JSON.parse(content));
            }
            catch {
                /* malformed package.json: other rules still run */
            }
        }
    }
    return { root, files, packageJsons, tracked: git?.tracked };
}
/** Globs from `.vibescanignore` at the scan root, one per line, `#` for comments. */
function readIgnoreFile(root) {
    try {
        return readFileSync(join(root, ".vibescanignore"), "utf8")
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter((l) => l && !l.startsWith("#"));
    }
    catch {
        return [];
    }
}
/** Minimal glob support: `**`, `*` and `?`. */
export function globToRegExp(glob) {
    let re = "";
    for (let i = 0; i < glob.length; i++) {
        const c = glob[i];
        if (c === "*") {
            if (glob[i + 1] === "*") {
                re += ".*";
                i++;
                if (glob[i + 1] === "/")
                    i++;
            }
            else
                re += "[^/]*";
        }
        else if (c === "?")
            re += "[^/]";
        else
            re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
    return new RegExp(`^${re}(/.*)?$`);
}
