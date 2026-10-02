# BSA Operations Runbook

## Objetivo

Este runbook cobre os incidentes operacionais mínimos do piloto: health degradado, worker parado, fila acumulada, backup/restore e atualização com rollback.

## Sinais e endpoints

Use primeiro:

- `GET /health` — auth DB, asset store, fila e worker;
- `GET /api/v1/operations/assessment-queue` — fila, retries, leases e worker;
- `GET /api/v1/operations/alerts` — alertas operacionais;
- `GET /metrics` — métricas Prometheus;
- `GET /api/v1/operations/release-readiness` — gate do piloto.

Toda resposta HTTP possui `X-Request-ID`. Use esse ID para correlacionar eventos no log JSON da API.

## Worker parado ou stale

Sintomas:

- `active_workers=0`;
- `stale_workers>0`;
- jobs acumulando em `queued`;
- alerta `no_active_worker_with_backlog`.

Ações:

1. confirme `docker compose -f docker-compose.production.yml ps`;
2. consulte logs do `bsa-worker`;
3. reinicie somente o worker;
4. confirme heartbeat saudável em até 120 segundos;
5. valide que jobs expirados foram reprocessados ou marcados como falha após o limite de tentativas;
6. não reenvie manualmente jobs já em execução sem confirmar o estado da fila.

## Fila com backlog

Se `oldest_queued_age_seconds > 900`:

1. confirme worker ativo;
2. verifique retries e leases expirados;
3. valide conectividade de egress dos motores;
4. confirme que o grant de autorização e Scan Scope continuam válidos;
5. reduza novas execuções até normalizar a fila.

## Health degradado

Se `/health` retornar `degraded`:

1. identifique o componente em `components`;
2. para `auth_db` ou `asset_store`, não faça novas mudanças administrativas;
3. para `queue`, pause novas coletas ativas;
4. para worker, siga o procedimento de worker stale;
5. só libere operação normal quando `/health` e release-readiness estiverem sem falha obrigatória.

## Backup automático

O serviço `bsa-backup` executa backup online periódico dos quatro bancos SQLite.

Padrões:

- intervalo: 86400 segundos;
- retenção: 14 dias;
- volume: `bsa_backups`;
- diretório interno: `/backups`.

Variáveis:

- `BSA_BACKUP_INTERVAL_SECONDS`;
- `BSA_BACKUP_RETENTION_DAYS`.

Cada arquivo é validado após criação com manifesto, SHA-256 e `PRAGMA integrity_check`.

## Backup manual antes de mudança

```bash
docker compose -f docker-compose.production.yml exec api \
  python -m app.backup create /data/bsa-backup-pre-change.zip

docker compose -f docker-compose.production.yml exec api \
  python -m app.backup inspect /data/bsa-backup-pre-change.zip
```

Nunca prossiga com upgrade se o inspect falhar.

## Restore

1. confirme o arquivo com `inspect`;
2. pare API e worker;
3. preserve uma cópia dos bancos atuais;
4. execute restore com `--force`;
5. suba API/worker/web;
6. valide `/health`;
7. valide release-readiness;
8. valide tenants, usuários, assets, findings e CTEM;
9. execute um scan controlado autorizado.

Exemplo:

```bash
docker compose -f docker-compose.production.yml stop api worker

docker compose -f docker-compose.production.yml run --rm api \
  python -m app.backup restore /data/bsa-backup.zip --force

docker compose -f docker-compose.production.yml up -d api worker web
```

## Rollback de atualização

Se uma atualização causar regressão:

1. pare novas coletas;
2. preserve logs e request IDs do incidente;
3. volte para a imagem/tag anterior;
4. restaure backup apenas se houve migração ou alteração incompatível de estado;
5. execute health, release-readiness e smoke test;
6. reabra operação somente após validação.

## Critérios de escalonamento

Escalone como incidente de prioridade alta quando houver:

- auth DB indisponível;
- asset store indisponível;
- corrupção de backup;
- fila sem worker ativo com backlog;
- leases expirados recorrentes;
- falha obrigatória no release-readiness;
- perda de isolamento entre tenants;
- falha em prova de posse ou autorização de scan.


## Motores de assessment em produção

Os motores de assessment são opcionais e a disponibilidade real deve ser consultada em runtime. Não presuma que todos os backends estejam instalados ou configurados apenas porque a API expõe o perfil.

Endpoints de validação:

- `GET /api/v1/exposure/engines/health` — estado público dos perfis e percentual de cobertura;
- `GET /api/v1/exposure/assessment/capabilities?target=<alvo>` — capacidades operacionais para o alvo;
- `GET /api/v1/operations/release-readiness` — consolida `rapid_assessment_coverage` e `balanced_assessment_coverage`.

Estados de perfil:

- `ready` — todas as capacidades core do perfil têm pelo menos um backend operacional;
- `partial` — somente parte das capacidades core está operacional;
- `unavailable` — nenhuma capacidade core está operacional.

`partial` não significa falha do produto: significa cobertura incompleta. O relatório, console e operação devem tratar isso como cobertura parcial e não como resultado conclusivo de ausência de exposição.

### Restrição temporária do Nuclei em produção

Até existir fixação de IP por execução ou controle equivalente de egress, `POST /api/v1/dast/nuclei` aceita em produção somente alvo com IP público explícito.

Exemplos:

- permitido: `https://203.0.113.10/` quando o IP estiver autorizado e dentro do Scan Scope;
- bloqueado em produção: `https://app.exemplo.com/`;
- bloqueado em qualquer ambiente: loopback, RFC1918, link-local, CGNAT, nomes internos e outros alvos não públicos.

A validação ocorre antes do enfileiramento e é repetida no engine. Não contorne essa proteção no worker.

### Safe Web e demais capacidades

`dast.safe-web` continua sendo o caminho de avaliação web segura baseado nos probes internos de baixo impacto. Outros providers só contribuem quando o binário e sua configuração estiverem presentes no worker e o endpoint de capabilities os reportar como operacionais.

Antes de liberar um piloto ou janela de scan:

1. valide `release-readiness`;
2. consulte o health dos engines;
3. registre o percentual de cobertura do perfil escolhido;
4. confirme Scan Scope e authorization_ref;
5. se o perfil estiver `partial`, informe a limitação no relatório operacional;
6. não apresente ausência de finding como ausência de risco quando houver capability indisponível.
