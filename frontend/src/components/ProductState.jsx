import React from "react";
import{AlertTriangle,CloudOff,Inbox,LoaderCircle,Wifi}from"lucide-react";

export const PRODUCT_STATE_KIND={
 loading:"loading",
 empty:"empty",
 error:"error",
 offline:"offline",
 online:"online"
};

const ICONS={
 loading:LoaderCircle,
 empty:Inbox,
 error:AlertTriangle,
 offline:CloudOff,
 online:Wifi
};

export function normalizeCount(value){
 const n=Number(value);
 return Number.isFinite(n)&&n>=0?n:0;
}

export function normalizePercent(value){
 const n=Number(value);
 if(!Number.isFinite(n))return 0;
 return Math.max(0,Math.min(100,n));
}

export function ProductStatus({kind="empty",title,text,action,compact=false,role}){
 const Icon=ICONS[kind]||Inbox;
 const liveRole=role||(kind==="error"?"alert":"status");
 return <div className={`product-state product-state-${kind}${compact?" compact":""}`} role={liveRole}>
  <div className="product-state-icon"><Icon size={compact?16:20} className={kind==="loading"?"spin":""}/></div>
  <div className="product-state-copy">
   {title&&<strong>{title}</strong>}
   {text&&<span>{text}</span>}
  </div>
  {action&&<div className="product-state-action">{action}</div>}
 </div>;
}

export function ConnectivityState({online,restored,offlineText,onlineText}){
 if(!online)return <ProductStatus kind="offline" text={offlineText} compact/>;
 if(restored)return <ProductStatus kind="online" text={onlineText} compact/>;
 return null;
}
