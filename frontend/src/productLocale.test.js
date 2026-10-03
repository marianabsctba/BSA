import{describe,expect,it}from"vitest";
import{PRODUCT_COPY,productCopy,resolveProductLocale}from"./productLocale.js";

describe("product locale",()=>{
 it("resolves supported browser languages",()=>{
  expect(resolveProductLocale("pt-BR")).toBe("pt-BR");
  expect(resolveProductLocale("en-US")).toBe("en");
  expect(resolveProductLocale("es-ES")).toBe("es");
 });

 it("falls back safely to pt-BR",()=>{
  expect(resolveProductLocale("fr-FR")).toBe("pt-BR");
  expect(resolveProductLocale("")).toBe("pt-BR");
 });

 it("keeps critical experience copy complete in every locale",()=>{
  for(const locale of ["pt-BR","en","es"]){
   expect(PRODUCT_COPY[locale].boundary.title).toBeTruthy();
   expect(PRODUCT_COPY[locale].boundary.retry).toBeTruthy();
   expect(PRODUCT_COPY[locale].experience.offline).toBeTruthy();
   expect(PRODUCT_COPY[locale].experience.skip).toBeTruthy();
  }
 });

 it("returns section copy using the resolved locale",()=>{
  expect(productCopy("experience","en-GB").skip).toBe("Skip to content");
  expect(productCopy("boundary","es-MX").retry).toBe("Intentar de nuevo");
 });
});
