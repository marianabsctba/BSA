import{describe,expect,it}from"vitest";
import{normalizeCount,normalizePercent,PRODUCT_STATE_KIND}from"./ProductState.jsx";

describe("ProductState primitives",()=>{
 it("normalizes invalid counts without inventing values",()=>{
  expect(normalizeCount(7)).toBe(7);
  expect(normalizeCount("12")).toBe(12);
  expect(normalizeCount(-1)).toBe(0);
  expect(normalizeCount("unknown")).toBe(0);
 });

 it("clamps percentages to the visual 0-100 contract",()=>{
  expect(normalizePercent(64)).toBe(64);
  expect(normalizePercent(146)).toBe(100);
  expect(normalizePercent(-9)).toBe(0);
  expect(normalizePercent("bad")).toBe(0);
 });

 it("keeps the shared state vocabulary stable",()=>{
  expect(PRODUCT_STATE_KIND).toEqual({loading:"loading",empty:"empty",error:"error",offline:"offline",online:"online"});
 });
});
