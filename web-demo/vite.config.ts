import { defineConfig } from "vite";

export default defineConfig({
  // Relative asset URLs, so one build works at a domain root (Render, nginx) and at a
  // subpath (GitHub Pages serves this repo at /PCZT-Guard/).
  base: "./",
  build: {
    target: "es2022",
    // The wasm binary is ~1 MB; it is fetched once and cached, so the size warning is noise.
    chunkSizeWarningLimit: 2048,
  },
  server: {
    port: 5173,
  },
});
