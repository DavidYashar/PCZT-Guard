import { defineConfig } from "vite";

export default defineConfig({
  build: {
    target: "es2022",
    // The wasm binary is ~1 MB; it is fetched once and cached, so the size warning is noise.
    chunkSizeWarningLimit: 2048,
  },
  server: {
    port: 5173,
  },
});
