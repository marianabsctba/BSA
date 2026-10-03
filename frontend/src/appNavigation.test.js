import{describe,expect,it}from"vitest";
import{APP_ROUTE_IDS,APP_NAVIGATION,navGroups,navLabel}from"./appNavigation.js";

describe("app navigation contract",()=>{
 it("keeps every locale aligned to the route contract",()=>{
  for(const locale of ["pt-BR","en","es"]){
   expect(APP_NAVIGATION[locale].labels).toHaveLength(APP_ROUTE_IDS.length);
   expect(APP_NAVIGATION[locale].groups).toHaveLength(4);
  }
 });
 it("resolves known route labels",()=>{
  expect(navLabel("pt-BR","overview")).toBe("Visão de Exposição");
  expect(navLabel("en","easm")).toBe("External Surface");
  expect(navLabel("es","reports")).toBe("Informes");
 });
 it("falls back safely for unsupported locales and routes",()=>{
  expect(navGroups("fr")).toEqual(APP_NAVIGATION["pt-BR"].groups);
  expect(navLabel("fr","missing")).toBe("Governança");
 });
});
