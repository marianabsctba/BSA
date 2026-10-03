import React from "react";
import{Activity,Boxes,ChevronRight,Cpu,FileText,Globe2,Layers3,LogOut,Menu,PanelLeftClose,Radar,RefreshCw,Search,ShieldAlert,SlidersHorizontal,Target,TriangleAlert,Waypoints,Clock3}from"lucide-react";
import{navGroups,navLabel}from"../appNavigation.js";

const cx=(...x)=>x.filter(Boolean).join(" ");

export function AppSidebar({locale,active,setActive,sidebar,setSidebar,ctemCount=0,me,onLogout}){
 const groups=navGroups(locale);
 const nav=[
  [groups[0],[["overview",Activity]]],
  [groups[1],[["easm",Radar],["surface",Globe2],["assets",Boxes],["vuln",ShieldAlert],["risk",TriangleAlert],["tech",Cpu]]],
  [groups[2],[["ctem",Target],["queue",Waypoints],["story",Clock3],["reports",FileText]]],
  [groups[3],[["policy",SlidersHorizontal],["admin",Layers3]]]
 ];
 const protectedLabel=locale==="en"?"protected":locale==="es"?"protegido":"protegido";
 const logoutLabel=locale==="en"?"Sign out":locale==="es"?"Salir":"Sair";
 return <aside className={cx("sidebar",!sidebar&&"collapsed")}>
  <div className="side-brand"><div className="panther"><img src="/assets/bsa-panther.svg" alt="Be Safe"/></div>{sidebar&&<div><b>BE SAFE</b><span>ASM / EXPOSURE</span></div>}</div>
  <nav>{nav.map(([group,items])=><React.Fragment key={group}>{sidebar&&<div className="nav-group-label">{group}</div>}{items.map(([id,Icon])=><button key={id} className={cx("nav-item",active===id&&"active")} onClick={()=>{setActive(id);if(window.innerWidth<=1050)setSidebar(false)}}><Icon size={18}/>{sidebar&&<><span>{navLabel(locale,id)}</span>{(id==="ctem"||id==="queue")&&ctemCount>0&&<em>{ctemCount}</em>}</>}</button>)}</React.Fragment>)}</nav>
  {sidebar&&<div className="side-bottom"><div className="tenant-card"><div className="eyebrow">TENANT</div><strong>{me?.tenant_id||"—"}</strong><span>{me?.role||"—"} · {protectedLabel}</span></div><button className="nav-item" onClick={onLogout}><LogOut size={17}/>{logoutLabel}</button></div>}
 </aside>;
}

export function AppTopbar({locale,active,sidebar,setSidebar,loading,onOpenCommand,onChangeLocale,onRefresh,me}){
 const t=locale==="en"?{collapse:"Collapse navigation",expand:"Expand navigation",language:"Language",live:"LIVE INTELLIGENCE",refresh:"Refresh intelligence",search:"Search",open:"Open command palette"}:locale==="es"?{collapse:"Contraer navegación",expand:"Expandir navegación",language:"Idioma",live:"INTELIGENCIA EN VIVO",refresh:"Actualizar inteligencia",search:"Buscar",open:"Abrir paleta de comandos"}:{collapse:"Recolher navegação",expand:"Expandir navegação",language:"Idioma",live:"INTELIGÊNCIA AO VIVO",refresh:"Atualizar inteligência",search:"Buscar",open:"Abrir paleta de comandos"};
 return <header className="topbar"><button className="icon-btn" aria-label={sidebar?t.collapse:t.expand} title={sidebar?t.collapse:t.expand} onClick={()=>setSidebar(!sidebar)}>{sidebar?<PanelLeftClose size={19}/>:<Menu size={19}/>}</button><div className="crumb"><span>Be Safe ASM</span><ChevronRight size={14}/><b>{navLabel(locale,active)}</b></div><div className="top-actions"><button className="command-trigger" onClick={onOpenCommand} aria-label={t.open}><Search size={14}/><span>{t.search}</span><kbd>⌘K</kbd></button><select className="locale-select" value={locale} onChange={e=>onChangeLocale(e.target.value)} aria-label={t.language}><option value="pt-BR">PT</option><option value="en">EN</option><option value="es">ES</option></select><div className="status"><i/> {t.live}</div><button className="icon-btn" aria-label={t.refresh} title={t.refresh} onClick={onRefresh}><RefreshCw size={17} className={loading?"spin":""}/></button><div className="avatar">{(me?.name||"M").slice(0,1).toUpperCase()}</div></div></header>;
}

export default function AppShell({locale,active,setActive,sidebar,setSidebar,loading,ctemCount,me,onLogout,onOpenCommand,onChangeLocale,onRefresh,children}){
 const closeLabel=locale==="en"?"Close navigation":locale==="es"?"Cerrar navegación":"Fechar navegação";
 const updating=locale==="en"?"Updating data":locale==="es"?"Actualizando datos":"Atualizando dados";
 return <div className="app-shell">
  <AppSidebar locale={locale} active={active} setActive={setActive} sidebar={sidebar} setSidebar={setSidebar} ctemCount={ctemCount} me={me} onLogout={onLogout}/>
  {sidebar&&<button className="sidebar-backdrop" aria-label={closeLabel} onClick={()=>setSidebar(false)}/>} 
  <main className="workspace">{loading&&<div className="top-progress" aria-label={updating}><i/></div>}<AppTopbar locale={locale} active={active} sidebar={sidebar} setSidebar={setSidebar} loading={loading} onOpenCommand={onOpenCommand} onChangeLocale={onChangeLocale} onRefresh={onRefresh} me={me}/>{children}</main>
 </div>;
}
