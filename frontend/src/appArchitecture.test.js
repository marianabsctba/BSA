import fs from "node:fs";
import path from "node:path";
import {describe,expect,it} from "vitest";

const appPath=path.resolve(process.cwd(),"src/App.jsx");

describe("frontend architecture seam",()=>{
 it("keeps App.jsx as a thin composition entrypoint",()=>{
  const source=fs.readFileSync(appPath,"utf8");
  expect(source.length).toBeLessThan(2000);
  expect(source).not.toContain("function EASM(");
  expect(source).not.toContain("function Governance(");
  expect(source).not.toContain("function VulnerabilityIntel(");
  expect(source).not.toContain("function CTEM(");
 });
});
