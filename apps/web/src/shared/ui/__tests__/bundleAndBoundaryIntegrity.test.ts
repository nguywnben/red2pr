// @vitest-environment node
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import viteConfig from "../../../../vite.config";

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = resolve(THIS_DIR, "../../../..");
const REPO_ROOT = resolve(WEB_ROOT, "../..");
const SRC_ROOT = join(WEB_ROOT, "src");

function walkFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      results.push(...walkFiles(full));
    } else {
      results.push(full);
    }
  }
  return results;
}

describe("U04 Bundle Security, Astryx Isolation & AGENTS.md Integrity (FE-05, SEC-040, OQ-20)", () => {
  it("preserves root AGENTS.md byte-for-byte (OQ-20 SHA-256 contract)", () => {
    const agentsPath = join(REPO_ROOT, "AGENTS.md");
    const normalizedLf = readFileSync(agentsPath, "utf8").replace(/\r\n/g, "\n");
    const digest = createHash("sha256").update(normalizedLf, "utf8").digest("hex");
    expect(digest).toBe("1fe195214a28f40d3b621a75da55390d8033aadeace35e9aefa4599146b97509");
  });

  it("isolates all @astryxdesign/* imports inside src/shared/{ui,theme,i18n}/ (FE-05)", () => {
    const allowedPrefixes = ["shared/ui/", "shared/theme/", "shared/i18n/"];
    const sourceFiles = walkFiles(SRC_ROOT).filter(
      (filePath) => filePath.endsWith(".ts") || filePath.endsWith(".tsx"),
    );

    const violations: string[] = [];
    for (const filePath of sourceFiles) {
      const rel = relative(SRC_ROOT, filePath).replace(/\\/g, "/");
      const isAllowed = allowedPrefixes.some((prefix) => rel.startsWith(prefix));
      if (isAllowed) {
        continue;
      }
      const content = readFileSync(filePath, "utf8");
      if (/@astryxdesign\//.test(content)) {
        violations.push(rel);
      }
    }

    expect(violations).toEqual([]);
  });

  it("prohibits dangerouslySetInnerHTML, eval(), and new Function() across web source files (SEC-040)", () => {
    const prodSourceFiles = walkFiles(SRC_ROOT).filter(
      (filePath) =>
        (filePath.endsWith(".ts") || filePath.endsWith(".tsx")) &&
        !filePath.includes("__tests__"),
    );

    const violations: string[] = [];
    for (const filePath of prodSourceFiles) {
      const rel = relative(SRC_ROOT, filePath).replace(/\\/g, "/");
      const content = readFileSync(filePath, "utf8");
      if (
        content.includes("dangerouslySetInnerHTML") ||
        /\beval\s*\(/.test(content) ||
        /\bnew\s+Function\s*\(/.test(content)
      ) {
        violations.push(rel);
      }
    }

    expect(violations).toEqual([]);
  });

  it("locks Vite production config to sourcemap: false and envPrefix: VITE_PUBLIC_ with zero .map files in dist/", () => {
    const resolved = typeof viteConfig === "function" ? undefined : viteConfig;
    expect(resolved?.envPrefix).toBe("VITE_PUBLIC_");
    expect(resolved?.build?.sourcemap).toBe(false);

    const distDir = join(WEB_ROOT, "dist");
    if (existsSync(distDir)) {
      const distFiles = walkFiles(distDir);
      const mapFiles = distFiles.filter((filePath) => filePath.endsWith(".map"));
      expect(mapFiles).toEqual([]);

      // NFR-11: initial gzipped JS bundle must stay well below 350 KiB
      const jsFiles = distFiles.filter((filePath) => filePath.endsWith(".js"));
      const totalGzipJsBytes = jsFiles.reduce(
        (acc, filePath) => acc + gzipSync(readFileSync(filePath)).byteLength,
        0,
      );
      expect(totalGzipJsBytes).toBeGreaterThan(0);
      expect(totalGzipJsBytes).toBeLessThan(350 * 1024);
    }
  });
});
