import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies the API so the console talks to a local Night Shift backend.
const backend = process.env.BEACON_API ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, target: "es2020" },
  server: { port: 5173, proxy: { "/api": backend, "/voice": backend } },
});
