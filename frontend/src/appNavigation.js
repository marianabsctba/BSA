export const APP_ROUTE_IDS=["overview","easm","vuln","risk","ctem","queue","policy","tech","surface","assets","story","reports","admin"];

export const APP_NAVIGATION={
 "pt-BR":{
  labels:["Visão de Exposição","Superfície Externa","Vulnerabilidades","Inteligência de Risco","CTEM","Fila CTEM","Política de Risco","Tecnologia","Superfície de Ataque","Inventário de Ativos","Linha do Tempo","Relatórios","Governança"],
  groups:["VISÃO","EXPOSIÇÃO","OPERAÇÃO","ADMINISTRAÇÃO"]
 },
 en:{
  labels:["Exposure Overview","External Surface","Vulnerabilities","Risk Intelligence","CTEM","CTEM Queue","Risk Policy","Technology","Attack Surface","Asset Inventory","Change Storyline","Reports","Governance"],
  groups:["OVERVIEW","EXPOSURE","OPERATIONS","ADMINISTRATION"]
 },
 es:{
  labels:["Visión de Exposición","Superficie Externa","Vulnerabilidades","Inteligencia de Riesgo","CTEM","Cola CTEM","Política de Riesgo","Tecnología","Superficie de Ataque","Inventario de Activos","Línea de Cambios","Informes","Gobernanza"],
  groups:["VISIÓN","EXPOSICIÓN","OPERACIÓN","ADMINISTRACIÓN"]
 }
};

export function navLabel(locale,id){
 const l=APP_NAVIGATION[locale]||APP_NAVIGATION["pt-BR"];
 const index=APP_ROUTE_IDS.indexOf(id);
 return l.labels[index]||l.labels[l.labels.length-1];
}

export function navGroups(locale){
 return (APP_NAVIGATION[locale]||APP_NAVIGATION["pt-BR"]).groups;
}
