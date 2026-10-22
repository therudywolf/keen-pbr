import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import viteCompression from "vite-plugin-compression"
import { constants } from "zlib"
import { defineConfig } from "vite"

import { demoApiPlugin } from "./demo/vite-plugin-demo-api"

const textAssetPattern = /\.(html?|css|js|mjs|cjs|jsx|ts|tsx|json|svg|txt|xml|wasm|map)$/i

// https://vite.dev/config/
const isDemoMode = (mode: string) => mode === "demo"

const routerUrl = process.env.ROUTER_URL || "http://192.168.54.1:12121"

// The package ships only the pre-compressed .gz text assets; the daemon
// inflates them for the rare client without gzip support. `vite preview`
// (Playwright) cannot do that, so the e2e build keeps the originals.
const keepUncompressedAssets =
  process.env.KEEN_PBR_FRONTEND_KEEP_UNCOMPRESSED === "1"

export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    tailwindcss(),
    ...(isDemoMode(mode) ? [demoApiPlugin()] : []),
    viteCompression({
      algorithm: "gzip",
      ext: ".gz",
      threshold: 0,
      filter: textAssetPattern,
      deleteOriginFile: !keepUncompressedAssets,
      disable: mode === "development",
      compressionOptions: {
        level: constants.Z_BEST_COMPRESSION,
      },
    }),
  ],
  build: {
    outDir: process.env.KEEN_PBR_FRONTEND_OUT_DIR || "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 768,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) {
            return undefined
          }
          if (
            id.includes("@tanstack/react-query") ||
            id.includes("@tanstack/query-core")
          ) {
            return "tanstack-query"
          }
          if (
            id.includes("@tanstack/react-form") ||
            id.includes("@tanstack/form-core") ||
            id.includes("@tanstack/store")
          ) {
            return "tanstack-form"
          }
          if (
            id.includes("i18next") ||
            id.includes("react-i18next") ||
            id.includes("i18next-")
          ) {
            return "i18n"
          }
          if (id.includes("lucide-react")) {
            return "icons"
          }
          return "vendor"
        },
      },
    },
  },
  server: isDemoMode(mode)
    ? {
        host: true,
        port: 5173,
        strictPort: true,
      }
    : {
        proxy: {
          "/api": {
            target: routerUrl,
            changeOrigin: true,
            // The daemon refuses requests whose Origin is not its own (CSRF
            // guard). Present the dev UI's own requests as same-origin; any
            // other page's Origin is passed on unchanged and still refused.
            configure: (proxy) => {
              proxy.on("proxyReq", (proxyReq, req) => {
                const origin = req.headers.origin
                if (origin && origin === `http://${req.headers.host}`) {
                  proxyReq.setHeader("origin", new URL(routerUrl).origin)
                }
              })
            },
          },
        },
      },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}))
