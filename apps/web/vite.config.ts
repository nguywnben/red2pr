import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  // Prevent accidental leakage of server-side secrets into import.meta.env
  envPrefix: "VITE_PUBLIC_",
  esbuild: {
    legalComments: "none",
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api/v1": {
        target: "http://127.0.0.1:4280",
        changeOrigin: false,
      },
    },
  },
  build: {
    target: "es2022",
    // Exclude sourcemaps from public production bundle (SEC / U04)
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
          if (
            id.includes("node_modules/react/") ||
            id.includes("node_modules/react-dom/") ||
            id.includes("node_modules/react-router/")
          ) {
            return "vendor-react";
          }
          if (id.includes("node_modules/@tanstack/") || id.includes("node_modules/zod/")) {
            return "vendor-data";
          }
          return undefined;
        },
      },
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/shared/test/setup.ts"],
    maxWorkers: 4,
    testTimeout: 30000,
    css: {
      include: [/tokens\.css$/],
    },
    watch: false,
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
});
