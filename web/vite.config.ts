import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During local dev, proxy /api to the hub so the SPA and API share an origin.
const HUB = process.env.HUB_URL ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: HUB, changeOrigin: true },
    },
  },
});
