# BSA — Be Safe ASM

**Versão atual:** `0.4.0`

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

## Estado atual — v0.4.0 Intelligence

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

**Extensão planejada — Web Exposure & Artifact Discovery**
- descoberta controlada de artefatos públicos: `robots.txt`, `sitemap.xml`, `.well-known/`, `security.txt`, manifests e arquivos públicos;
- detecção de `swagger.json`, `openapi.json` e especificações de API expostas;
- análise segura de JSON/XML/YAML/TXT públicos;
- extração de URLs, hosts, domínios, caminhos, referências de cloud e outros indicadores observados;
- descoberta de caminhos referenciados em HTML/JavaScript público, sem exploração ou autenticação;
- source maps e artefatos JS somente quando publicamente acessíveis;
- classificação de evidência como **observada, inferida ou candidata**;
- correlação dos artefatos com aplicações, tecnologias, endpoints e ativos já conhecidos;
- limites de tamanho, profundidade, quantidade e tempo para impedir abuso de recursos;
- integração com Evidence Graph, Change Intelligence e Risk Engine.

O objetivo não é transformar o BSA em um directory brute-forcer: é construir **Web Exposure Intelligence**, aproveitando informações que a própria aplicação publica.

### Fase 3 — Infrastructure & Exposure Intelligence
- Shadow IT e ownership;
- dangling DNS e sinais de takeover com validação humana;
- certificados, SANs e relações de infraestrutura;
- ASN/IP correlation e infraestrutura compartilhada;
- CDN/WAF/reverse proxy fingerprinting;
- cloud exposure e identificação de provedores;
- mudanças de ASN/IP e infraestrutura;
- correlação domínio → subdomínio → certificado → IP → ASN → tecnologia → serviço → API;
- contextualização de exposição e attack paths;
- correlação de vulnerability intelligence somente quando houver evidência técnica suficiente.

### Fase 4 — Intelligence & Risk
- vulnerability intelligence;
- CPE e identificação de versão;
- CVE/EPSS/KEV/exploit context;
- Risk Engine explicável;
- confidence/evidence quality;
- blast radius;
- attack paths;
- CTEM prioritization;
- remediation impact simulation.

### Fase 5 — Operations
Workflows, responsáveis, SLA, exceções, comentários, reteste, Jira/GLPI/Freshservice, webhooks e exportações.

### Fase 6 — BSA Intelligence Graph
Grafo de ativos e relacionamentos, confiança por evidência, descoberta recursiva controlada, infraestrutura compartilhada, threat intelligence e priorização baseada em contexto.

### Fase 4 — Operations
Workflows, responsáveis, SLA, exceções, comentários, reteste, Jira/GLPI/Freshservice, webhooks e exportações.

### Fase 5 — BSA Intelligence Graph
Grafo de ativos e relacionamentos, confiança por evidência, descoberta recursiva controlada e priorização baseada em contexto.

## Princípios de segurança

O BSA será orientado à **descoberta e validação defensiva de ativos autorizados**. A plataforma deve privilegiar técnicas passivas e probes seguros, com limites de execução, identificação da origem das evidências e escopo explicitamente configurado.

## Executar

### Produção / piloto

O caminho padrão para qualquer ambiente compartilhado, piloto ou servidor é o compose endurecido de produção:

```bash
cp .env.example .env
# substitua segredo, senha administrativa, hosts/origins e demais valores antes de iniciar
docker compose -f docker-compose.production.yml up -d --build
```

Console: `http://127.0.0.1:8080`

A API permanece na rede interna do compose e deve ser publicada somente por reverse proxy/TLS aprovado.

### Desenvolvimento local

O compose de desenvolvimento é somente para workstation local. Ele não contém segredo ou senha padrão e falha se `BSA_JWT_SECRET` e `BSA_ADMIN_PASSWORD` não forem definidos. As portas também ficam limitadas a `127.0.0.1`.

```bash
export BSA_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export BSA_ADMIN_PASSWORD="defina-uma-senha-local-forte"
docker compose up --build
```

Console: `http://127.0.0.1:8080`  
API: `http://127.0.0.1:8000`  
Swagger de desenvolvimento: `http://127.0.0.1:8000/docs`

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


## IA local / Exposure Copilot

O BSA pode usar **Ollama no próprio servidor** para interpretar evidências do Exposure Graph sem enviar dados do tenant para uma API externa.

Variáveis de produção:
- `BSA_AI_ENABLED=1`
- `BSA_OLLAMA_URL=http://ai-proxy:11435`
- `BSA_OLLAMA_PROXY_TOKEN=<segredo aleatório com 32+ caracteres>`
- `BSA_OLLAMA_MODEL=qwen2.5:7b`
- `BSA_AI_TIMEOUT=15`

Em produção, a API não acessa o Ollama diretamente. O tráfego passa por um proxy interno autenticado e o Ollama fica isolado em uma rede dedicada.

Após subir o stack, baixe o modelo no servidor:

```bash
docker exec bsa-ollama ollama pull qwen2.5:7b
```

O Copilot continua funcionando em **fallback determinístico** se o modelo estiver indisponível. A IA recebe somente o conjunto de evidências selecionado para a pergunta e é instruída a não inventar fatos.

Endpoints:
- `GET /api/v1/exposure/ai/status`
- `GET /api/v1/exposure/copilot?question=...`

A arquitetura é local-first: **internet não é necessária para inferência**, depois que o modelo estiver instalado no servidor.


## Integração SIEM / Syslog

O BSA possui dois caminhos complementares de integração com SOC/SIEM:

- `GET /api/v1/integrations/siem/export` — feed JSON unificado para coleta via API;
- Syslog estruturado — UDP, TCP ou TLS, com TLS/6514 como padrão recomendado.

O feed unificado inclui findings de exposição e eventos CTI/DRP, incluindo vazamentos de credenciais/dados, sem exportar segredos brutos.

Endpoints operacionais:

- `GET /api/v1/integrations/siem/status` — mostra se Syslog está configurado;
- `POST /api/v1/integrations/siem/syslog/test` — envia um evento de teste;
- `POST /api/v1/integrations/siem/syslog/push` — envia o lote atual filtrável por `since` e `limit`.

Configuração recomendada:

```env
BSA_SYSLOG_HOST=siem.exemplo.local
BSA_SYSLOG_PORT=6514
BSA_SYSLOG_TRANSPORT=tls
BSA_SYSLOG_FACILITY=16
BSA_SYSLOG_APP_NAME=be-safe-asm
BSA_SYSLOG_TIMEOUT=5
```

Para coletores com CA privada, configure `BSA_SYSLOG_CA_FILE` e, quando necessário, `BSA_SYSLOG_SERVER_NAME`. O transporte TLS valida o certificado do coletor.

O Syslog usa framing compatível com RFC5424 e payload JSON estruturado. Campos sensíveis como senha, token ou segredo bruto são removidos antes do envio.

## Digital Risk Protection (DRP)

O BSA unifica sinais externos em uma camada de **DRP + CTI + EASM**, com eventos para phishing, abuso de marca, perfis falsos, apps falsos, malware, vazamento de dados, VIP/executivos, Deep/Dark Web e supply chain.

O desenho segue padrões de DRP com correlação de EASM e CTI, brand protection, leak monitoring, threat hunting e VIP protection. A implementação do BSA é vendor-neutral, orientada a evidências e mantém separadas observação, correlação, classificação de risco e resposta operacional.


## Piloto distribuído — 31 empresas

Para distribuição externa, não use o perfil de desenvolvimento. O piloto deve ser iniciado com BSA_ENV=production, segredo JWT próprio, credenciais administrativas próprias e escopo explícito por tenant.

### Checklist obrigatório antes de entregar

1. Copie .env.example para .env e substitua todos os valores de exemplo.
2. Gere um BSA_JWT_SECRET aleatório com pelo menos 32 caracteres.
3. Use uma senha administrativa longa e exclusiva; nunca reutilize a senha de demonstração.
4. Configure BSA_ALLOWED_ORIGINS e BSA_ALLOWED_HOSTS somente para os domínios usados pelo piloto.
5. Mantenha BSA_DEMO_DATA=0 em produção.
6. Cadastre os domínios/hosts autorizados no Scope do tenant.
7. Antes de criar um Scan Scope de domínio em produção, conclua a prova de posse por DNS TXT ou `.well-known`.
8. Só depois da prova validada, crie o Scan Scope e atribua-o ao usuário operador.
9. Crie grants temporários de autorização para scans ativos, com `authorization_ref`, alvo/pattern, usuário e expiração. O criador do grant não pode ser o beneficiário.
10. Configure a política de retenção da tenant e execute primeiro o dry-run antes de qualquer limpeza.
11. Consulte /api/v1/operations/release-readiness e não libere o piloto enquanto houver required_failures.
12. Prefira docker-compose.production.yml, que mantém API, proxy de IA e Ollama em redes internas separadas e não publica a porta da API diretamente.
13. Faça backup do volume bsa_data antes de atualizar o piloto.
14. Instale o modelo local do Ollama antes de isolar a rede interna.
15. Nunca exponha o endpoint administrativo diretamente à Internet sem uma camada TLS/reverse proxy e controles de acesso.

### Backup, restore e upgrade do piloto

Antes de qualquer atualização do piloto, gere um snapshot consistente dos quatro bancos SQLite:

```bash
docker compose -f docker-compose.production.yml exec api \
  python -m app.backup create /data/bsa-backup.zip
```

Valide o arquivo antes de mover ou armazenar:

```bash
docker compose -f docker-compose.production.yml exec api \
  python -m app.backup inspect /data/bsa-backup.zip
```

O backup usa a API online do SQLite, executa `PRAGMA integrity_check` e registra SHA-256 no manifesto. Para restore, pare API e worker primeiro. O restore recusa sobrescrever bancos existentes por padrão:

```bash
docker compose -f docker-compose.production.yml stop api worker
docker compose -f docker-compose.production.yml run --rm api \
  python -m app.backup restore /data/bsa-backup.zip --force
docker compose -f docker-compose.production.yml up -d api worker web
```

Após upgrade ou restore, confirme:

1. `/health` da API;
2. `/api/v1/operations/release-readiness`;
3. worker com status saudável em `/api/v1/operations/assessment-queue`;
4. tenants, usuários, assets, findings, CTEM e histórico;
5. um scan controlado de validação antes de reabrir a operação normal.

O `docker-compose.production.yml` possui healthcheck da API e do worker. O worker só fica saudável quando o heartbeat persistido estiver recente.


### Prova de posse para Scan Scope ativo

Em produção, um domínio só pode virar Scan Scope ativo depois de uma prova de posse válida.

Fluxo:

1. `POST /api/v1/domain-ownership/proofs` com o domínio e método `dns_txt` ou `well_known`;
2. publique exatamente o challenge retornado:
   - DNS TXT em `_bsa-verify.<domínio>`; ou
   - conteúdo do challenge em `https://<domínio>/.well-known/be-safe-asm-verification`;
3. chame `POST /api/v1/domain-ownership/proofs/{proof_id}/verify`;
4. somente depois da confirmação crie o Scan Scope ativo.

A verificação `.well-known` reaplica validação de destino público e evita seguir redirects. O mesmo domínio registrável não pode ficar ativo em tenants diferentes sem aprovação de superadmin.

### Segurança de discovery

O Discovery possui validação contra destinos não públicos e redirecionamentos para endereços privados, reduzindo risco de SSRF. Probes de portas e TLS também passam pelo gate de alvo externo. A expansão recursiva permanece limitada por profundidade e quantidade de ativos.

**Importante:** autorização do cliente continua sendo requisito operacional. O software não deve ser usado para testar ativos fora do escopo autorizado.
