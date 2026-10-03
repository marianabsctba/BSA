import React from "react";
import {RefreshCw,ShieldCheck} from "lucide-react";
import {PRODUCT_COPY,browserProductLocale} from "./productLocale.js";
import {ProductStatus} from "./components/ProductState.jsx";

export default class ProductBoundary extends React.Component{
 constructor(props){super(props);this.state={failed:false,nonce:0};}
 static getDerivedStateFromError(){return{failed:true};}
 componentDidCatch(error,info){
  if(import.meta.env?.DEV)console.error("BSA frontend boundary",error,info);
 }
 retry=()=>this.setState(s=>({failed:false,nonce:s.nonce+1}));
 render(){
  if(!this.state.failed)return <React.Fragment key={this.state.nonce}>{this.props.children}</React.Fragment>;
  const t=PRODUCT_COPY[browserProductLocale()].boundary;
  const actions=<div className="product-fallback-actions">
   <button className="primary" onClick={this.retry}><RefreshCw size={16}/>{t.retry}</button>
   <button className="secondary" onClick={()=>window.location.reload()}>{t.reload}</button>
  </div>;
  return <main className="product-fallback" role="alert">
   <section className="product-fallback-card">
    <div className="eyebrow">{t.eyebrow}</div>
    <ProductStatus kind="error" title={t.title} text={t.body} action={actions}/>
    <small><ShieldCheck size={14}/>{t.safe}</small>
   </section>
  </main>;
 }
}
