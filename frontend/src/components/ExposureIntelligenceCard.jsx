import React from "react";
import { BrainCircuit, ShieldCheck, AlertTriangle } from "lucide-react";

export default function ExposureIntelligenceCard({ score = 0, confidence = "unknown", findings = [] }) {
  return (
    <section className="exposure-intelligence-card">
      <div className="exposure-intelligence-header">
        <BrainCircuit size={20} />
        <div>
          <strong>Exposure Intelligence</strong>
          <span>Contexto de risco baseado em evidências</span>
        </div>
      </div>

      <div className="exposure-metrics">
        <div>
          <small>Risk score</small>
          <b>{score}</b>
        </div>
        <div>
          <small>Confiança</small>
          <b>{confidence}</b>
        </div>
      </div>

      <div className="exposure-findings">
        {findings.slice(0, 5).map((item, index) => (
          <div key={index}>
            {item.severity === "high" ? <AlertTriangle size={16} /> : <ShieldCheck size={16} />}
            <span>{item.title || item}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
