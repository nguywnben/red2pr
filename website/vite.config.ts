import { copyFileSync, existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

function githubPagesArtifactsPlugin(): Plugin {
  return {
    name: "red2pr-github-pages-artifacts",
    closeBundle() {
      const distDir = resolve(import.meta.dirname, "dist");
      const indexHtml = resolve(distDir, "index.html");
      const notFoundHtml = resolve(distDir, "404.html");
      const noJekyll = resolve(distDir, ".nojekyll");
      if (existsSync(indexHtml)) {
        copyFileSync(indexHtml, notFoundHtml);
        writeFileSync(noJekyll, "", "utf8");
      }
    },
  };
}

export default defineConfig({
  base: "/red2pr/",
  plugins: [react(), githubPagesArtifactsPlugin()],
  envPrefix: "VITE_PUBLIC_",
  esbuild: {
    legalComments: "none",
  },
  server: {
    host: "127.0.0.1",
    port: 5180,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 4180,
    strictPort: true,
  },
  build: {
    target: "es2022",
    sourcemap: false,
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      treeshake: {
        preset: "smallest",
      },
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/@astryxdesign/")) {
            return "vendor-astryx";
          }
          if (id.includes("node_modules/react/") || id.includes("node_modules/react-dom/")) {
            return "vendor-react";
          }
          return undefined;
        },
      },
    },
  },
});
