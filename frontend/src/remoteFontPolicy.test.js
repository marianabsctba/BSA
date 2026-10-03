import { describe, expect, it } from "vitest";
import { stripRemoteFontImports } from "../vite.config.js";

describe("stripRemoteFontImports",()=>{
  it("removes remote Google Fonts imports from the application stylesheet",()=>{
    const plugin=stripRemoteFontImports();
    const css="@import url('https://fonts.googleapis.com/css2?family=DM+Mono&family=Manrope');\n:root{color:#fff}";
    const transformed=plugin.transform(css,"/workspace/frontend/src/styles.css");
    expect(transformed).not.toContain("fonts.googleapis.com");
    expect(transformed).toContain(":root{color:#fff}");
  });

  it("does not rewrite unrelated modules",()=>{
    const plugin=stripRemoteFontImports();
    expect(plugin.transform("export const x=1","/workspace/frontend/src/x.js")).toBeNull();
  });
});
