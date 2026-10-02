# Security & Product Maturity Remediation Tracker

Base: parecer técnico de pentest gray box + avaliação de maturidade de produto (02/10/2026).

Regra de fechamento: nenhum item é considerado concluído apenas por mudança de código. Cada item precisa de:
1. correção implementada;
2. teste automatizado ou verificação operacional objetiva;
3. evidência de CI/reteste;
4. documentação quando o controle depende de operação humana.

## Pentest Gray Box — 14 achados

| ID | Tema | Prioridade | Estado atual | Critério de fechamento |
|---|---|---:|---|---|
| BSA-01 | Escalonamento vertical via papel customizado com users:write | P0 | Implementado; regressão criada | CI verde + reteste impedindo promoção/criação de admin por papel delegado |
| BSA-02 | SSRF / varredura de rede interna no assessment e motores | P0 | Implementado; worker isolado da rede AI | CI verde + reteste de loopback/RFC1918/link-local/CGNAT/nome interno + validação de follow-ups |
| BSA-03 | Grant autodeclarado / wildcard / escopo amplo | P0 | Implementado parcialmente | CI verde + segregação + limites de escopo + prova de posse + política para sobreposição entre tenants |
| BSA-04 | Caminho padrão de execução inseguro | P0 | Implementado | CI verde + README seguro + compose sem segredo/senha default + bind localhost |
| BSA-05 | DoS de login por IP do proxy / conta-alvo | P1 | Concluído e validado no CI | IP real confiável no proxy + throttle persistente sem lockout global abusável + regressões |
| BSA-06 | Enumeração de usuário por timing | P1 | Concluído e validado no CI | Hash fictício PBKDF2 para usuário ausente + regressão |
| BSA-07 | MFA: reauth, replay, cobertura, chave, recovery | P1 | Concluído e validado no CI | Reauth em enroll/disable, anti-replay, MFA para todos, política por tenant, chave MFA separada, recovery codes |
| BSA-08 | Assessment ignora active scan scope | P1 | Concluído e validado no CI | govern_active_scan centralizado em assessment/retest/worker + testes de contrato |
| BSA-09 | Coleta ativa por GET / execução síncrona | P2 | Aberto/parcial | POST para ações mutantes + fila para toda coleta ativa relevante |
| BSA-10 | /auth/permissions 500 em custom role | P2 | Aberto | tenant_id no role_permissions + erro tratado + teste |
| BSA-11 | Sessão/rate-limit: persistência, idle timeout, password change | P2 | Quase concluído: persistência, idle timeout e password change validados no CI | idle timeout + cookie usa TOKEN_TTL + troca de senha com reauth + testes |
| BSA-12 | Prompt injection / Ollama sem autenticação | P2 | Parcial | untrusted data delimitado, schema de saída, limite de grafo, sugestão explícita, proxy/token para Ollama |
| BSA-13 | Auditoria adulterável / posse DRP | P3 | Parcial | hash chain real + export SIEM/WORM + tenant ownership de event_id + chave de conflito tenant-scoped |
| BSA-14 | HSTS/proxy/supply-chain | P3 | Parcial | HSTS na borda + forwarded proto fixo + Actions por SHA + imagens por digest + SAST + Trivy + SBOM |

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
- [ ] Migrar assets/findings para PostgreSQL.
- [ ] Introduzir camada de repository.
- [ ] Migrações versionadas com Alembic.
- [ ] Remover ALTER TABLE oportunista do caminho normal de conexão.
- [ ] Reduzir custo linear de tenant_scope.
- [ ] Quebrar app/main.py em routers por domínio.
- [ ] Mover lógica de negócio dos handlers para services.
- [ ] Toda coleta ativa relevante passa por fila.
- [ ] Workers dedicados por classe de motor quando necessário.
- [ ] Egress de motores restringido por política de rede.
- [ ] API stateless preparada para múltiplas réplicas.
- [ ] Estratégia de failover/HA.

### Operação e observabilidade
- [ ] Logging estruturado JSON.
- [ ] request_id/correlation_id.
- [ ] tenant_id e user_id em contexto de log seguro.
- [ ] Métricas de latência, fila, retries, erros e duração por motor.
- [ ] Prometheus/OpenTelemetry.
- [ ] Tracing.
- [ ] Alertas básicos operacionais.
- [ ] /health real para DB/fila/dependências essenciais.
- [x] Backup SQLite online verificado.
- [x] Teste automatizado de restauração.
- [ ] Backup agendado e retenção operacional documentada.
- [ ] Runbook de incidentes/falhas de worker/restore.

### Qualidade e CI/CD
- [ ] Medição de cobertura + threshold mínimo.
- [ ] Ruff/flake8.
- [ ] Mypy/pyright.
- [ ] Testes de frontend.
- [ ] Modularização do App.jsx.
- [ ] SAST (Bandit/Semgrep).
- [ ] Trivy/image scan.
- [ ] SBOM.
- [ ] Assinatura/attestation de artefatos.
- [ ] Actions pinadas por SHA.
- [ ] Imagens base pinadas por digest.
- [ ] Pipeline de deploy/homologação.
- [ ] Versionamento único API/console/docs.
- [ ] CHANGELOG e tags de release.

### Documentação e governança
- [ ] Separar README de marketing, roadmap e operação.
- [ ] Guia de implantação.
- [ ] Guia de operação.
- [ ] Modelo de dados.
- [ ] Threat model.
- [ ] Política de versionamento.
- [ ] Referência de API para produção.
- [ ] Procedimento formal de aprovação de scans.
- [ ] Procedimento de prova de posse.
- [ ] Artefatos LGPD para dados DRP/leaks/perfis.
- [ ] Política de retenção documentada por categoria de dado.
- [ ] Trilha de auditoria inviolável e exportável.

### Produto / capacidades anunciadas
- [ ] Change Intelligence baseado em histórico real em todos os fluxos.
- [ ] Política de risco realmente persistida por tenant.
- [ ] SLA MSSP configurável e baseado em janela temporal real.
- [x] DRP/leaks com score/correlação/evidência.
- [ ] Takedown com integração real ou posicionamento comercial reduzido.
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
- [ ] MFA obrigatório por política de tenant.
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
