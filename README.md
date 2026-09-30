# BSA — Be Safe ASM

<p align="center">
  <img src="assets/bsa-readme-logo.jpg" alt="BSA Panther" width="520">
</p>

<p align="center">
  <strong>External Attack Surface Management • Continuous Discovery • Exposure Prioritization</strong><br>
  <sub>Powered by Mariana BS</sub>
</p>

---

## Enterprise Exposure Intelligence

A `main` agora inclui um núcleo de exposição explicável e uma coleta controlada por alvo explícito:

- **Asset Exposure Engine**: score 0–100 por ativo, com fatores e justificativas rastreáveis.
- **Exposure Prioritization**: ranking dos ativos por exposição e faixa de risco.
- **Discovery API**: DNS + HTTP + TLS para um alvo informado pelo operador; sem varredura recursiva automática.
- **Evidence confidence**: cada evidência mantém origem, confiança e contexto.
- **Dashboard**: console Be Safe preto/rosa com descoberta, priorização e contexto operacional.
- **MSSP/CTEM foundation**: arquitetura preparada para ownership, grafo, threat intelligence, integrações e tenants.

### Discovery API

```text
POST /api/v1/discovery
{"target":"cliente.com.br","checks":["dns","http","tls"]}
```

Use somente em ativos para os quais você possui autorização. A coleta é limitada ao alvo fornecido e não realiza enumeração recursiva por padrão.

### Exposure API

- `GET /api/v1/exposure` — priorização por ativo.
- `GET /api/v1/score` — postura agregada + breakdown por ativo.

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


## O que diferencia o BSA de um ASM convencional

O BSA foi evoluído para combinar **EASM + exposição contextual + CTEM operacional**, sem depender de contagem bruta de ativos.

### 1. Evidence-first Asset Graph
Cada ativo é tratado como uma identidade sustentada por evidências, com origem, confiança, quantidade de evidências, histórico e relacionamento. Isso reduz a tendência de transformar qualquer observação externa em ativo confirmado.

### 2. Ownership Confidence
Ownership é uma hipótese mensurável: `confirmed`, `probable` ou `candidate`. O sistema pode separar superfície confirmada de shadow/third-party antes de gerar métricas executivas.

### 3. Scoped Multi-Tenant ASM
O mesmo console suporta tenants isolados, RBAC, scopes por padrão de domínio/host e grupos de ativos. Um analista pode operar apenas sobre o conjunto autorizado.

### 4. Attack-path contextual
O BSA correlaciona exposição, criticidade, findings e relacionamentos para produzir caminhos de risco e explicar o elo mais fraco. O objetivo é priorizar exposição alcançável, não simplesmente CVE/finding count.

### 5. Exposure Reduction, não quantidade de alertas
A plataforma expõe métricas de postura e redução de exposição, permitindo acompanhar ativos Internet-facing, findings abertos, ativos não confirmados e score agregado. A redução histórica só é declarada quando existem snapshots comparáveis.

### 6. Asset 360
Cada ativo possui uma visão operacional com identidade, ownership, risco, blast radius, findings, remediação, evidências, histórico e grafo.

### 7. CTEM-ready
O fluxo foi desenhado em torno de:
`Scope → Discovery → Classification → Prioritization → Validation → Mobilization → Remediation → Retest`.

### 8. Diferencial Be Safe
- PT-BR nativo;
- MSSP/multi-tenant;
- RBAC + scoped RBAC;
- audit trail;
- explicabilidade de risco;
- ownership baseado em evidências;
- baixo impacto por padrão;
- autorização e escopo explícitos;
- arquitetura aberta para SIEM/SOAR/ITSM/CTI;
- foco em números que podem virar decisão operacional.

## Benchmark de capacidades

As plataformas líderes atuais enfatizam descoberta contínua, visibilidade Internet-scale, validação de exposição, ownership, attack paths, contexto de negócio e workflows de remediação. O BSA está sendo construído para cobrir essas dimensões e adicionar **evidence confidence + scoped multi-tenancy + governança operacional** como diferenciais próprios.
