# Operação

## PostgreSQL opcional para assets/findings

O compose principal continua usando o backend legado por padrão. Para habilitar
PostgreSQL apenas para o repositório de assets/findings, suba o overlay junto
com o compose de produção:

```bash
export BSA_POSTGRES_PASSWORD='troque-esta-senha'
docker compose -f docker-compose.production.yml -f docker-compose.postgres.yml up -d
```

O overlay configura `BSA_ASSET_REPOSITORY_BACKEND=postgres` e
`BSA_DATABASE_URL` apenas no `api` e no `worker`, adiciona um PostgreSQL
com healthcheck e mantém o banco em uma rede interna dedicada. Auth, history e
jobs continuam no backend atual nesta etapa; a migração deles deve ser tratada
separadamente antes de remover os volumes SQLite.
