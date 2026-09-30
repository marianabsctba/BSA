# BSA — Be Safe ASM

<p align="center">
  <img src="assets/bsa-readme-logo.jpg" alt="BSA Panther" width="520">
</p>

<p align="center">
  <strong>External Attack Surface Management • Continuous Discovery • Exposure Prioritization</strong><br>
  <sub>Powered by Mariana BS</sub>
</p>

---

## O que é o BSA?

O **BSA (Be Safe ASM)** é a plataforma de **Attack Surface Management** da Be Safe, criada para descobrir, correlacionar, contextualizar e priorizar ativos expostos à Internet.

A proposta é ir além de uma lista de IPs e domínios: o BSA mantém um **inventário vivo da superfície de ataque**, registra evidências, identifica mudanças e transforma exposição técnica em uma fila de ação defensiva.

> O princípio é simples: **descobrir como um atacante enxerga a organização, mas entregar o resultado com governança, rastreabilidade e validação humana.**

## Estado atual — v0.2 Intelligence

O BSA já saiu do simples inventário e passou a trabalhar com contexto de superfície:

- descoberta de domínios, subdomínios, IPs, serviços e certificados;
- inventário externo com criticidade, origem e confiança da evidência;
- **ownership confidence** para diferenciar ativo confirmado, provável e candidato;
- **blast radius** por ativo;
- findings com severidade, confiança e score contextual;
- **Exposure Score explicável**, com penalidades rastreáveis;
- **Change Intelligence** para ativos novos e mudanças relevantes;
- **Asset Relationship Graph** para correlação entre domínio, host, IP e serviço;
- collectors de DNS, HTTP e TLS orientados a baixo impacto;
- dashboard preto + rosa da Be Safe;
- API REST;
- testes automatizados e CI;
- Docker;
- base pronta para CTEM, cloud exposure, brand monitoring e integrações SIEM/SOAR/ITSM.

### Diferencial de arquitetura

O BSA não assume que tudo o que foi encontrado pertence ao cliente. A plataforma trata **ownership como hipótese baseada em evidências**, reduzindo falso positivo e evitando inflar artificialmente a superfície de ataque.

Da mesma forma, risco não é calculado apenas por severidade: o contexto do ativo, criticidade, exposição e confiança entram na priorização.

## Arquitetura

```text
                    ┌────────────────────────────┐
                    │       BSA Web Console      │
                    │    Black / Pink / PT-BR    │
                    └─────────────┬──────────────┘
                                  │
                           REST API / FastAPI
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
       Asset Inventory      Exposure Engine      Change Engine
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                         Collector Framework
                                  │
         ┌──────────────┬─────────┼─────────┬──────────────┐
         │ DNS / RDAP   │ TLS/HTTP│ Ports   │ CT / Passive │
         └──────────────┴─────────┴─────────┴──────────────┘
```

## Roadmap técnico

### Fase 1 — Foundation
Inventário, API, dashboard, evidências, score e normalização.

### Fase 2 — Discovery Engine
DNS, RDAP/WHOIS, Certificate Transparency, HTTP/TLS, portas expostas, fingerprints e relacionamento entre ativos.

### Fase 3 — Intelligence
Shadow IT, dangling DNS, certificados, takeover signals, serviços administrativos, exposição de cloud, mudanças de ASN/IP e correlação de risco.

### Fase 4 — Operations
Workflows, responsáveis, SLA, exceções, comentários, reteste, Jira/GLPI/Freshservice, webhooks e exportações.

### Fase 5 — BSA Intelligence Graph
Grafo de ativos e relacionamentos, confiança por evidência, descoberta recursiva controlada e priorização baseada em contexto.

## Princípios de segurança

O BSA será orientado à **descoberta e validação defensiva de ativos autorizados**. A plataforma deve privilegiar técnicas passivas e probes seguros, com limites de execução, identificação da origem das evidências e escopo explicitamente configurado.

## Executar

```bash
docker compose up --build
```

Console: `http://localhost:8080`  
API: `http://localhost:8000`  
Swagger: `http://localhost:8000/docs`

---

**BSA • Be Safe ASM**  
**Powered by Mariana BS**
