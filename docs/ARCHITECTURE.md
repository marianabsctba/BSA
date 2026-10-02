# BSA — Arquitetura alvo

## Visão

O BSA será uma plataforma de External Attack Surface Management orientada a evidências. Cada ativo e finding deve ter origem, tempo de observação, confiança, relacionamento e histórico de mudança.

## Camadas

1. **Scope & Governance** — escopos autorizados, tenants, seeds, limites, exclusões e auditoria.
2. **Discovery** — DNS, RDAP, Certificate Transparency, TLS/HTTP, cloud hints e outras fontes de baixo impacto.
3. **Normalization** — representação canônica para domínio, subdomínio, IP, serviço, aplicação, certificado e recurso cloud.
4. **Correlation Graph** — relacionamentos entre ativos e evidências, deduplicação e ownership confidence.
5. **Exposure Engine** — findings, severidade, confiança, criticidade e score explicável.
6. **Change Engine** — first seen, last seen, new, changed, disappeared e resurrected.
7. **Operations** — workflows, owner, SLA, exceção, reteste, comentários e integrações.
8. **Experience** — dashboard, pesquisa, grafo, timeline, relatórios e API.

## Regra central

**Descoberto não significa automaticamente pertencente ao cliente.**

O ownership será calculado por evidências e poderá exigir validação humana antes de um ativo passar a compor a superfície confirmada.

## Segurança operacional

Collectors devem obedecer ao escopo. Novos probes ativos devem ser explicitamente classificados, limitados por taxa e desabilitados por padrão quando puderem produzir impacto.


## Cobertura e disponibilidade de motores

A arquitetura separa capacidade de produto de backend concreto. Perfis de assessment trabalham com capacidades lógicas e podem ser executados com cobertura `ready`, `partial` ou `unavailable`, conforme os providers realmente instalados e configurados no worker.

A API não deve inferir cobertura pelo nome do perfil. O estado é calculado pelo registry e exposto pelos endpoints de health/capabilities.

Em produção:

- engines ativos executam no worker com rede de egress dedicada;
- a API permanece sem egress direto para os motores;
- o Nuclei aceita apenas IP público explícito enquanto não houver pinning de IP por execução;
- hostname resolvido dinamicamente não deve ser repassado ao Nuclei nesse estágio;
- resultados de perfil parcial devem preservar a indicação de cobertura incompleta.

Esse desenho evita transformar indisponibilidade de um backend opcional em falso negativo silencioso.
