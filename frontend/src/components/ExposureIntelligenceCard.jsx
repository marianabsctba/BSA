import React from"react";
import{BrainCircuit,ShieldCheck,AlertTriangle}from"lucide-react";
import{ProductStatus,normalizeCount,normalizePercent}from"./ProductState.jsx";

const COPY={
 "pt-BR":{title:"Exposure Intelligence",sub:"Contexto de risco baseado em evidências",score:"Score de risco",confidence:"Confiança",empty:"Nenhum achado contextual",emptyText:"Os sinais aparecem quando houver evidência suficiente para contextualizar o risco."},
 en:{title:"Exposure Intelligence",sub:"Evidence-backed risk context",score:"Risk score",confidence:"Confidence",empty:"No contextual findings",emptyText:"Signals appear when enough evidence exists to contextualize risk."},
 es:{title:"Exposure Intelligence",sub:"Contexto de riesgo basado en evidencia",score:"Puntuación de riesgo",confidence:"Confianza",empty:"Sin hallazgos contextuales",emptyText:"Las señales aparecen cuando existe evidencia suficiente para contextualizar el riesgo."}
};

export function exposureBand(score){
 const n=normalizePercent(score);
 if(n>=80)return"critical";
 if(n>=60)return"high";
 if(n>=35)return"medium";
 return"low";
}

export default function ExposureIntelligenceCard({score=0,confidence=0,findings=[],locale="pt-BR"}){
 const t=COPY[locale]||COPY["pt-BR"];
 const safeScore=normalizePercent(score);
 const safeConfidence=normalizePercent(confidence);
 const items=Array.isArray(findings)?findings:[];
 const band=exposureBand(safeScore);
 return <section className="exposure-intelligence-card">
  <div className="exposure-intelligence-header">
   <BrainCircuit size={20}/>
   <div><strong>{t.title}</strong><span>{t.sub}</span></div>
   <span className={`easm-state ${band}`}>{safeScore}</span>
  </div>
  <div className="exposure-metrics">
   <div><small>{t.score}</small><b>{safeScore}</b></div>
   <div><small>{t.confidence}</small><b>{safeConfidence}%</b></div>
   <div><small>Signals</small><b>{normalizeCount(items.length)}</b></div>
  </div>
  <div className="exposure-findings">
   {items.length?items.slice(0,5).map((item,index)=>{
    const severity=String(item?.severity||"").toLowerCase();
    const hot=severity==="high"||severity==="critical";
    return <div key={item?.id||`${index}-${item?.title||item}`} className={hot?"hot":""}>
     {hot?<AlertTriangle size={16}/>:<ShieldCheck size={16}/>}<span>{item?.title||String(item)}</span>
    </div>;
   }):<ProductStatus kind="empty" title={t.empty} text={t.emptyText} compact/>}
  </div>
 </section>;
}
