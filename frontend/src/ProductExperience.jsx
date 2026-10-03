import React,{useEffect,useRef,useState}from"react";
import{CloudOff,Wifi,ArrowDown}from"lucide-react";

const copy={
 "pt-BR":{offline:"Você está offline. Os dados exibidos podem estar desatualizados.",online:"Conexão restabelecida.",skip:"Ir para o conteúdo",page:"Página atual"},
 en:{offline:"You are offline. Displayed data may be stale.",online:"Connection restored.",skip:"Skip to content",page:"Current page"},
 es:{offline:"Está sin conexión. Los datos mostrados pueden estar desactualizados.",online:"Conexión restablecida.",skip:"Ir al contenido",page:"Página actual"}
};

function locale(){
 const lang=(typeof navigator!=="undefined"?navigator.language:"")||"pt-BR";
 if(lang.toLowerCase().startsWith("en"))return"en";
 if(lang.toLowerCase().startsWith("es"))return"es";
 return"pt-BR";
}

export default function ProductExperience({children}){
 const[online,setOnline]=useState(()=>typeof navigator==="undefined"?true:navigator.onLine);
 const[restored,setRestored]=useState(false);
 const[route,setRoute]=useState("");
 const previousOnline=useRef(online);
 const t=copy[locale()];

 useEffect(()=>{
  const sync=()=>setOnline(navigator.onLine);
  window.addEventListener("online",sync);
  window.addEventListener("offline",sync);
  return()=>{window.removeEventListener("online",sync);window.removeEventListener("offline",sync)};
 },[]);

 useEffect(()=>{
  if(!previousOnline.current&&online){setRestored(true);const id=setTimeout(()=>setRestored(false),3200);previousOnline.current=online;return()=>clearTimeout(id)}
  previousOnline.current=online;
 },[online]);

 useEffect(()=>{
  if(typeof MutationObserver==="undefined")return;
  const read=()=>setRoute(document.querySelector(".crumb b")?.textContent?.trim()||"");
  read();
  const observer=new MutationObserver(read);
  observer.observe(document.body,{subtree:true,childList:true,characterData:true});
  return()=>observer.disconnect();
 },[]);

 const skip=()=>{
  const target=document.querySelector(".content");
  if(!target)return;
  target.setAttribute("tabindex","-1");
  target.focus({preventScroll:true});
  target.scrollIntoView({behavior:"smooth",block:"start"});
 };

 return <>
  <button className="ux-skip" onClick={skip}><ArrowDown size={14}/>{t.skip}</button>
  {!online&&<div className="ux-connectivity offline" role="status"><CloudOff size={15}/><span>{t.offline}</span></div>}
  {online&&restored&&<div className="ux-connectivity online" role="status"><Wifi size={15}/><span>{t.online}</span></div>}
  <div className="sr-only" aria-live="polite">{route?t.page+": "+route:""}</div>
  {children}
 </>;
}
