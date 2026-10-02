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
