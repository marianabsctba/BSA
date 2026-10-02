# Security & Product Maturity Remediation Tracker

Base: parecer técnico de pentest gray box + avaliação de maturidade de produto (02/10/2026).

Regra de fechamento: nenhum item é considerado concluído apenas por mudança de código. Cada item precisa de:
1. correção implementada;
2. teste automatizado ou verificação operacional objetiva;
3. evidência de CI e, quando exigido pelo parecer, reteste independente;
4. documentação quando o controle depende de operação humana.

## Pentest Gray Box — 14 achados

| ID | Tema | Prioridade | Estado atual | Critério de fechamento |
|---|---|---:|---|---|
| BSA-01 | Escalonamento vertical via papel customizado com users:write | P0 | Implementado; CI verde; reteste independente pendente | CI verde + reteste impedindo promoção/criação de admin por papel delegado |
| BSA-02 | SSRF / varredura de rede interna no assessment e motores | P0 | Implementado; CI verde; hostname do Nuclei bloqueado em produção; reteste independente pendente | CI verde + reteste de loopback/RFC1918/link-local/CGNAT/nome interno + validação de follow-ups |
| BSA-03 | Grant autodeclarado / wildcard / escopo amplo | P0 | Implementado; CI verde; reteste independente pendente | CI verde + segregação + limites de escopo + prova de posse + política para sobreposição entre tenants |
| BSA-04 | Caminho padrão de execução inseguro | P0 | Implementado; CI verde; reteste independente pendente | CI verde + README seguro + compose sem segredo/senha default + bind localhost |
| BSA-05 | DoS de login por IP do proxy / conta-alvo | P1 | Implementado; CI verde; reteste independente pendente | IP real confiável no proxy + throttle persistente sem lockout global abusável + regressões |
| BSA-06 | Enumeração de usuário por timing | P1 | Implementado; CI verde; reteste independente pendente | Hash fictício PBKDF2 para usuário ausente + regressão |
| BSA-07 | MFA: reauth, replay, cobertura, chave, recovery | P1 | Implementado; CI verde; reteste independente pendente | Reauth em enroll/disable, anti-replay, MFA para todos, política por tenant, chave MFA separada, recovery codes |
| BSA-08 | Assessment ignora active scan scope | P1 | Implementado; CI verde; reteste independente pendente | govern_active_scan centralizado em assessment/retest/worker + testes de contrato |
| BSA-09 | Coleta ativa por GET / execução síncrona | P2 | Implementado; CI verde; reteste independente pendente | POST para ações mutantes + fila para toda coleta ativa relevante |
| BSA-10 | /auth/permissions 500 em custom role | P2 | Implementado; CI verde; reteste independente pendente | tenant_id no role_permissions + erro tratado + teste |
| BSA-11 | Sessão/rate-limit: persistência, idle timeout, password change | P2 | Implementado; CI verde; reteste independente pendente | idle timeout + cookie usa TOKEN_TTL + troca de senha com reauth + testes |
| BSA-12 | Prompt injection / Ollama sem autenticação | P2 | Implementado; CI verde; reteste independente pendente | untrusted data delimitado, schema de saída, limite de grafo, sugestão explícita, proxy/token para Ollama |
| BSA-13 | Auditoria adulterável / posse DRP | P3 | Implementado; CI verde; reteste independente pendente | hash chain real + export SIEM/WORM + tenant ownership de event_id + chave de conflito tenant-scoped |
| BSA-14 | HSTS/proxy/supply-chain | P3 | Implementado; CI verde; reteste independente pendente | HSTS na borda + forwarded proto fixo + Actions por SHA + imagens por digest + SAST + Trivy + SBOM |

### Condições adicionais do parecer de pentest

- Reteste P0 com 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 e 100.64.0.0/10.
- Bloqueio de nomes de serviço internos.
- Procedimento formal de grant com segregação de funções.
- Prova de posse de domínio antes de scan ativo.
- Política para sobreposição do mesmo domínio entre tenants.
- release-readiness sem falhas obrigatórias no ambiente do piloto.

## Maturidade de Produto — Fundação obrigatória

### Arquitetura e escalabilidade
- [ ] Eliminar listas globais de assets/findings como fonte operacional.
- [x] Adapter PostgreSQL para assets/findings implementado, opt-in por ambiente; migração controlada SQLite → PostgreSQL com dry-run e reconciliação adicionada. Cutover real em ambiente ainda pendente.
- [x] Camada de repository introduzida com port de aplicação; routers desacoplados do store direto.
- [ ] Migrações versionadas com Alembic.
- [ ] Remover ALTER TABLE oportunista do caminho normal de conexão.
- [ ] Reduzir custo linear de tenant_scope.
- [x] Quebrar app/main.py em routers por domínio.
- [ ] Mover lógica de negócio dos handlers para services.
- [x] Toda coleta ativa relevante passa por fila.
- [x] Workers/executores separados por classe de operação com dispatcher próprio.
- [x] API isolada da rede de egress; motores ativos executam no worker com egress dedicado e validação/pinning de alvos.
- [ ] API stateless preparada para múltiplas réplicas. Assets/findings já possuem backend PostgreSQL compartilhável; auth/history/jobs ainda exigem evolução.
- [ ] Estratégia de failover/HA.

### Operação e observabilidade
- [x] Logging estruturado JSON.
- [x] request_id/correlation_id.
- [x] tenant_id e user_id em contexto de log seguro.
- [x] Métricas de latência, fila, retries, erros e duração por motor.
- [x] Prometheus endpoint operacional.
- [ ] Tracing.
- [x] Alertas básicos operacionais.
- [x] /health mínimo de liveness e /ready detalhado para DB/fila/dependências essenciais.
- [x] Backup SQLite online verificado.
- [x] Teste automatizado de restauração.
- [x] Backup agendado e retenção operacional documentada.
- [x] Runbook de incidentes/falhas de worker/restore.

### Qualidade e CI/CD
- [x] Medição de cobertura + threshold mínimo.
- [x] Ruff crítico.
- [x] Mypy em módulos críticos.
- [x] Testes de frontend.
- [ ] Modularização do App.jsx.
- [x] SAST (Bandit).
- [x] Trivy/image scan.
- [x] SBOM CycloneDX.
- [ ] Assinatura/attestation de artefatos.
- [x] Actions pinadas por SHA.
- [x] Imagens base pinadas por digest.
- [ ] Pipeline de deploy/homologação.
- [x] Versionamento único API/console/docs.
- [ ] CHANGELOG e tags de release.

### Documentação e governança
- [ ] Separar README de marketing, roadmap e operação.
- [ ] Guia de implantação.
- [x] Guia de operação.
- [ ] Modelo de dados.
- [ ] Threat model.
- [ ] Política de versionamento.
- [ ] Referência de API para produção.
- [ ] Procedimento formal de aprovação de scans.
- [ ] Procedimento de prova de posse.
- [ ] Artefatos LGPD para dados DRP/leaks/perfis.
- [ ] Política de retenção documentada por categoria de dado.
- [x] Trilha de auditoria tamper-evident, verificável e exportável.

### Produto / capacidades anunciadas
- [ ] Change Intelligence baseado em histórico real em todos os fluxos.
- [x] Política de risco realmente persistida por tenant.
- [x] SLA MSSP configurável e baseado em janela temporal real.
- [x] DRP/leaks com score/correlação/evidência.
- [ ] Avaliação de qualidade da IA local.
- [x] SIEM API pull.
- [x] Syslog UDP/TCP/TLS.
- [ ] Outbox/retry persistente para SIEM push.
- [ ] Webhooks.
- [ ] Jira.
- [ ] GLPI.
- [ ] Freshservice.
- [ ] SSO OIDC.
- [ ] SSO SAML.
- [x] MFA obrigatório por política de tenant.
- [ ] HA / múltiplas réplicas.

## Ordem de execução

1. Fechar e retestar P0.
2. Fechar P1 (BSA-05..08).
3. Fechar P2 (BSA-09..12).
4. Fechar P3 (BSA-13..14).
5. Fundação de piloto: observabilidade, health real, docs/versionamento.
6. Fundação de escala: PostgreSQL/repositories/Alembic/modularização/fila.
7. Fundação GA: SSO, integrações, HA, LGPD, auditoria inviolável.

## Definition of Done

Este tracker só pode ser considerado concluído quando:
- todos os itens acima estiverem marcados como concluídos;
- CI estiver verde com os novos controles;
- reteste gray box não reabrir P0/P1;
- release-readiness do piloto estiver sem falhas obrigatórias;
- não houver capacidade anunciada como pronta se ainda estiver em estado beta/esboço/planejado.


### Pendências do Reteste nº 3

- [x] R3-01 — referências de testes migradas após modularização; CI voltou a verde.
- [x] R2-01 — headers de segurança preservados nas locations do nginx e validados no smoke test.
- [x] BSA-02 residual — Nuclei com hostname bloqueado em produção até pinning/egress equivalente.
- [x] R2-02 — limitação e cobertura dos motores em produção documentadas no runbook e arquitetura.
- [x] R2-03 — superadmin pode registrar aprovação de IP para tenant-alvo explícito.
- [x] R2-04 — atraso bloqueante removido; CI verde. Reteste independente pendente.
- [x] R3-02 — login válido não é rejeitado apenas por pressão de NAT compartilhado; CI verde. Reteste independente pendente.
- [x] BSA-05 residual — pressão global por conta adicionada sem lockout rígido do titular; CI verde. Reteste independente pendente.
- [x] R3-03 — repository layer, tenant_scope unificado, port de aplicação, adapter PostgreSQL, overlay opt-in e migração verificada implementados. Cutover real/múltiplas réplicas e reteste independente ainda pendentes.


## Próxima onda — evolução de produto e motores

Prioridade após consolidar as pendências de parecer e validar o cutover de persistência:

1. Discovery/EASM: cobertura, deduplicação, confiança, ownership, expansão inteligente e correlação histórica.
2. Vulnerability/Assessment: cobertura real de providers, normalização de evidência, correlação CVE/CPE/CVSS e redução de falso positivo.
3. CTI/DRP/Leaks: fontes, correlação entre eventos, credenciais vazadas, brand abuse, evidência e workflow de resposta.
4. Risk/Exposure: contextualização por criticidade, attack paths, exposição externa, probabilidade, impacto e explicabilidade.
5. SIEM/Integrações: outbox/retry persistente, webhooks e conectores operacionais.
6. IA local: avaliação de qualidade, guardrails, explicabilidade e uso assistivo no discovery/correlação, sem decisão autônoma de alto impacto.
7. Escala: mover auth/history/jobs para backend compartilhado, múltiplas réplicas, HA e migrações versionadas.
8. UX: modularizar App.jsx e melhorar fluxo operacional por persona sem esconder evidência técnica.

Regra: cada evolução de motor deve entrar com telemetria, testes de regressão, critério de cobertura e release-readiness correspondente.
