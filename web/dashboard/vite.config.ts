// EDR-GUI-02 D2/D3/D8: a static SPA built into the dashboard binary's embedded assets.
// The page is served at "/" (the default GUI since 2026-11-23); its files keep the /next/ base.
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vitest/config";

const dashboard = process.env.THEMIS_DASHBOARD_URL ?? "http://localhost:8090";

export default defineConfig({
  base: "/next/",
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: {
    outDir: "../../cmd/dashboard/static/next",
    emptyOutDir: true,
    sourcemap: false,
    // D8: the hashed files live under assets/ so the server can cache them forever.
    assetsDir: "assets",
  },
  server: {
    // `make web-dev`: hot reload here, everything server-side from a running dashboard.
    proxy: {
      "/api": dashboard,
      "/whoami": dashboard,
      "/login": dashboard,
      "/logout": dashboard,
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["src/test/setup.ts"],
    css: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/main.tsx", "src/types/**", "src/test/**", "src/**/*.test.{ts,tsx}"],
      thresholds: { lines: 80, functions: 80, statements: 80, branches: 70 },
    },
  },
});
