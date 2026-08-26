import { lstat, readFile, readdir } from "node:fs/promises";
import { extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { Finding } from "@synsec/core";
import type { RepositoryMetadata } from "@synsec/report";

const ignoredDirectories = new Set([
  ".git",
  ".hg",
  ".svn",
  ".idea",
  ".vscode",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  ".venv",
  "venv",
  "target",
  "bin",
  "obj",
  ".synsec",
]);

const languageByExtension: Record<string, string> = {
  ".js": "JavaScript",
  ".mjs": "JavaScript",
  ".cjs": "JavaScript",
  ".jsx": "JavaScript",
  ".ts": "TypeScript",
  ".mts": "TypeScript",
  ".cts": "TypeScript",
  ".tsx": "TypeScript",
  ".py": "Python",
  ".go": "Go",
  ".rs": "Rust",
  ".java": "Java",
  ".kt": "Kotlin",
  ".kts": "Kotlin",
  ".rb": "Ruby",
  ".php": "PHP",
  ".cs": "C#",
  ".c": "C",
  ".h": "C/C++ Header",
  ".cc": "C++",
  ".cpp": "C++",
  ".cxx": "C++",
  ".swift": "Swift",
  ".scala": "Scala",
  ".sh": "Shell",
  ".bash": "Shell",
  ".ps1": "PowerShell",
  ".tf": "Terraform",
  ".sol": "Solidity",
  ".ex": "Elixir",
  ".exs": "Elixir",
  ".dart": "Dart",
  ".lua": "Lua",
  ".r": "R",
  ".R": "R",
};

export interface RepositoryFile {
  path: string;
  size: number;
}

export interface RepositoryInventory {
  metadata: RepositoryMetadata;
  files: RepositoryFile[];
}

export interface FindingContext {
  path: string;
  startLine: number;
  endLine: number;
  excerpt: string;
  truncated: boolean;
}

function insideRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function walk(root: string, maxFiles: number): Promise<RepositoryFile[]> {
  const output: RepositoryFile[] = [];
  const stack = [root];

  while (stack.length > 0 && output.length < maxFiles) {
    const current = stack.pop();
    if (!current) break;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (output.length >= maxFiles) break;
      if (entry.isSymbolicLink()) continue;
      const absolute = join(current, entry.name);
      if (!insideRoot(root, absolute)) continue;

      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) stack.push(absolute);
        continue;
      }
      if (!entry.isFile()) continue;

      const stat = await lstat(absolute).catch(() => undefined);
      if (!stat?.isFile()) continue;
      output.push({
        path: relative(root, absolute).replaceAll(sep, "/"),
        size: stat.size,
      });
    }
  }
  return output;
}

function addFramework(frameworks: Set<string>, name: string): void {
  frameworks.add(name);
}

async function detectNodeFrameworks(root: string, frameworks: Set<string>): Promise<void> {
  const path = join(root, "package.json");
  const content = await readFile(path, "utf8").catch(() => undefined);
  if (!content) return;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return;
  }
  const dependencyMaps = [parsed.dependencies, parsed.devDependencies];
  const dependencies = new Set<string>();
  for (const value of dependencyMaps) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    for (const key of Object.keys(value as Record<string, unknown>)) dependencies.add(key);
  }
  const mappings: Array<[string, string]> = [
    ["next", "Next.js"],
    ["react", "React"],
    ["express", "Express"],
    ["fastify", "Fastify"],
    ["@nestjs/core", "NestJS"],
    ["h3", "H3"],
    ["nuxt", "Nuxt"],
    ["svelte", "Svelte"],
    ["@sveltejs/kit", "SvelteKit"],
    ["vue", "Vue"],
    ["astro", "Astro"],
    ["koa", "Koa"],
    ["hono", "Hono"],
  ];
  for (const [pkg, framework] of mappings) if (dependencies.has(pkg)) addFramework(frameworks, framework);
}

async function detectPythonFrameworks(root: string, frameworks: Set<string>): Promise<void> {
  const candidates = ["requirements.txt", "pyproject.toml", "Pipfile"];
  const text = (await Promise.all(candidates.map((name) => readFile(join(root, name), "utf8").catch(() => "")))).join("\n").toLowerCase();
  if (/\bdjango\b/.test(text)) addFramework(frameworks, "Django");
  if (/\bfastapi\b/.test(text)) addFramework(frameworks, "FastAPI");
  if (/\bflask\b/.test(text)) addFramework(frameworks, "Flask");
  if (/\bstarlette\b/.test(text)) addFramework(frameworks, "Starlette");
}

async function detectOtherFrameworks(root: string, frameworks: Set<string>): Promise<void> {
  const goMod = await readFile(join(root, "go.mod"), "utf8").catch(() => "");
  if (goMod.includes("github.com/gin-gonic/gin")) addFramework(frameworks, "Gin");
  if (goMod.includes("github.com/gofiber/fiber")) addFramework(frameworks, "Fiber");
  if (goMod.includes("github.com/labstack/echo")) addFramework(frameworks, "Echo");

  const composer = await readFile(join(root, "composer.json"), "utf8").catch(() => "");
  if (composer.includes("laravel/framework")) addFramework(frameworks, "Laravel");
  if (composer.includes("symfony/")) addFramework(frameworks, "Symfony");

  const pom = await readFile(join(root, "pom.xml"), "utf8").catch(() => "");
  if (pom.includes("spring-boot")) addFramework(frameworks, "Spring Boot");
}

export async function inventoryRepository(rootPath: string, maxFiles = 20_000): Promise<RepositoryInventory> {
  const root = resolve(rootPath);
  const files = await walk(root, maxFiles);
  const languages: Record<string, number> = {};
  for (const file of files) {
    const language = languageByExtension[extname(file.path)];
    if (!language) continue;
    languages[language] = (languages[language] ?? 0) + 1;
  }

  const frameworks = new Set<string>();
  await Promise.all([
    detectNodeFrameworks(root, frameworks),
    detectPythonFrameworks(root, frameworks),
    detectOtherFrameworks(root, frameworks),
  ]);

  return {
    metadata: {
      languages,
      frameworks: [...frameworks].sort(),
      fileCount: files.length,
    },
    files,
  };
}

export async function getFindingContext(rootPath: string, finding: Finding, radius = 20): Promise<FindingContext | undefined> {
  const location = finding.location;
  if (!location?.path) return undefined;
  const root = resolve(rootPath);
  const normalizedRelative = location.path.replaceAll("/", sep).replaceAll("\\", sep);
  const candidate = resolve(root, normalizedRelative);
  if (!insideRoot(root, candidate)) return undefined;

  const stat = await lstat(candidate).catch(() => undefined);
  if (!stat?.isFile() || stat.size > 1_000_000) return undefined;
  const content = await readFile(candidate, "utf8").catch(() => undefined);
  if (content === undefined || content.includes("\u0000")) return undefined;

  const lines = content.split(/\r?\n/);
  const focus = Math.max(1, location.startLine ?? 1);
  const startLine = Math.max(1, focus - radius);
  const endLine = Math.min(lines.length, (location.endLine ?? focus) + radius);
  const excerpt = lines
    .slice(startLine - 1, endLine)
    .map((line, index) => `${String(startLine + index).padStart(5)} | ${line}`)
    .join("\n");

  return {
    path: relative(root, candidate).replaceAll(sep, "/"),
    startLine,
    endLine,
    excerpt,
    truncated: startLine > 1 || endLine < lines.length,
  };
}
