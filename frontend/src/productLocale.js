export const PRODUCT_COPY={
 "pt-BR":{
  boundary:{eyebrow:"EXPERIÊNCIA PROTEGIDA",title:"O console encontrou um erro de interface.",body:"Os dados do tenant não foram alterados. Recarregue a interface para tentar novamente.",retry:"Tentar novamente",reload:"Recarregar console",safe:"Falha isolada no frontend"},
  experience:{offline:"Você está offline. Os dados exibidos podem estar desatualizados.",online:"Conexão restabelecida.",skip:"Ir para o conteúdo",page:"Página atual"}
 },
 en:{
  boundary:{eyebrow:"PROTECTED EXPERIENCE",title:"The console hit an interface error.",body:"Tenant data was not changed. Reload the interface to try again.",retry:"Try again",reload:"Reload console",safe:"Frontend failure isolated"},
  experience:{offline:"You are offline. Displayed data may be stale.",online:"Connection restored.",skip:"Skip to content",page:"Current page"}
 },
 es:{
  boundary:{eyebrow:"EXPERIENCIA PROTEGIDA",title:"La consola encontró un error de interfaz.",body:"Los datos del tenant no fueron modificados. Recargue la interfaz para intentarlo de nuevo.",retry:"Intentar de nuevo",reload:"Recargar consola",safe:"Falla aislada en el frontend"},
  experience:{offline:"Está sin conexión. Los datos mostrados pueden estar desactualizados.",online:"Conexión restablecida.",skip:"Ir al contenido",page:"Página actual"}
 }
};

export function resolveProductLocale(language=""){
 const lang=String(language||"").trim().toLowerCase();
 if(lang.startsWith("en"))return"en";
 if(lang.startsWith("es"))return"es";
 return"pt-BR";
}

export function browserProductLocale(){
 const language=typeof navigator!=="undefined"?navigator.language:"";
 return resolveProductLocale(language);
}

export function productCopy(section,language){
 const locale=resolveProductLocale(language);
 return PRODUCT_COPY[locale]?.[section]||PRODUCT_COPY["pt-BR"][section];
}
