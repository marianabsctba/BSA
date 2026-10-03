import React from "react";
import {AlertTriangle,RefreshCw,ShieldCheck} from "lucide-react";

const copy={
 "pt-BR":{eyebrow:"EXPERIÊNCIA PROTEGIDA",title:"O console encontrou um erro de interface.",body:"Os dados do tenant não foram alterados. Recarregue a interface para tentar novamente.",retry:"Tentar novamente",reload:"Recarregar console",safe:"Falha isolada no frontend"},
 en:{eyebrow:"PROTECTED EXPERIENCE",title:"The console hit an interface error.",body:"Tenant data was not changed. Reload the interface to try again.",retry:"Try again",reload:"Reload console",safe:"Frontend failure isolated"},
 es:{eyebrow:"EXPERIENCIA PROTEGIDA",title:"La consola encontró un error de interfaz.",body:"Los datos del tenant no fueron modificados. Recargue la interfaz para intentarlo de nuevo.",retry:"Intentar de nuevo",reload:"Recargar consola",safe:"Falla aislada en el frontend"}
};

function browserLocale(){
 const lang=(typeof navigator!=="undefined"?navigator.language:"")||"pt-BR";
 if(lang.toLowerCase().startsWith("es"))return "es";
 if(lang.toLowerCase().startsWith("en"))return "en";
 return "pt-BR";
}

export default class ProductBoundary extends React.Component{
 constructor(props){super(props);this.state={failed:false,nonce:0};}
 static getDerivedStateFromError(){return{failed:true};}
 componentDidCatch(error,info){
  if(import.meta.env?.DEV)console.error("BSA frontend boundary",error,info);
 }
 retry=()=>this.setState(s=>({failed:false,nonce:s.nonce+1}));
 render(){
  if(!this.state.failed)return <React.Fragment key={this.state.nonce}>{this.props.children}</React.Fragment>;
  const t=copy[browserLocale()];
  return <main className="product-fallback" role="alert">
   <section className="product-fallback-card">
    <div className="product-fallback-icon"><AlertTriangle size={24}/></div>
    <div className="eyebrow">{t.eyebrow}</div>
    <h1>{t.title}</h1>
    <p>{t.body}</p>
    <div className="product-fallback-actions">
     <button className="primary" onClick={this.retry}><RefreshCw size={16}/>{t.retry}</button>
     <button className="secondary" onClick={()=>window.location.reload()}>{t.reload}</button>
    </div>
    <small><ShieldCheck size={14}/>{t.safe}</small>
   </section>
  </main>;
 }
}
