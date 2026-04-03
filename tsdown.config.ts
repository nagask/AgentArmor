import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/entry.ts"],
  format: "esm",
  outDir: "dist",
  clean: true,
});
