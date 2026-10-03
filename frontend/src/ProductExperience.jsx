import React,{useEffect,useRef,useState}from"react";
import{CloudOff,Wifi,ArrowDown}from"lucide-react";
import{PRODUCT_COPY,browserProductLocale}from"./productLocale.js";

export default function ProductExperience({children}){
 const[online,setOnline]=useState(()=>typeof navigator==="undefined"?true:navigator.onLine);
 const[restored,setRestored]=useState(false);
 const[route,setRoute]=useState("");
 const previousOnline=useRef(online);
 const t=PRODUCT_COPY[browserProductLocale()].experience;

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
