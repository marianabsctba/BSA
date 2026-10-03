import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export function stripRemoteFontImports() {
  return {
    name: "bsa-local-font-policy",
    enforce: "pre",
    transform(code, id) {
      if (!id.replaceAll("\\", "/").endsWith("/styles.css")) return null;
      return code.replace(
        /^@import\s+url\(["']?https:\/\/fonts\.googleapis\.com\/[^;]+;\s*/m,
        ""
      );
    }
  };
}

export default defineConfig({
  plugins: [stripRemoteFontImports(), react()],
  server: { host: "127.0.0.1", port: 5173, strictPort: true },
  build: {
    sourcemap: false,
    target: "es2022",
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          charts: ["recharts"],
          icons: ["lucide-react"]
        }
      }
    }
  }
});
