# Plataforma SAST & DevSecOps

Projeto Integrador — Engenharia de Software (FIAP).

Plataforma de **Static Application Security Testing (SAST)** que analisa código-fonte Python **sem executá-lo**, detecta vulnerabilidades por meio de uma Árvore de Sintaxe Abstrata (AST) e de análise de fluxo de dados (*taint analysis*), usa um **LLM local (Ollama)** para classificar a severidade e sugerir correções, e se integra ao pipeline **CI/CD (GitHub Actions)** como um *Security Gate* que bloqueia Pull Requests com falhas críticas.

- **Linguagem-alvo analisada:** Python
- **Repositório:** https://github.com/wendelldsant/sast-devsecops-platform

### Alunos envolvidos

| Aluno | RM | GitHub |
|---|---|---|
| Augusto Rocha Silva | RM556316 | [augustorocha27](https://github.com/orgs/FIAP-3ESR-2026/people/augustorocha27) |
| Erik Yuuta Goto | RM558076 | [erikgotoo](https://github.com/orgs/FIAP-3ESR-2026/people/erikgotoo) |
| Guilherme Vieira Augusto | RM557264 | [guiaugustou](https://github.com/orgs/FIAP-3ESR-2026/people/guiaugustou) |
| Wendell dos Santos Silva | RM558859 | [wendelldsant](https://github.com/orgs/FIAP-3ESR-2026/people/wendelldsant) |

---

## Sumário

1. [Funcionalidades](#1-funcionalidades)
2. [Arquitetura](#2-arquitetura)
3. [Stack e justificativas](#3-stack-e-justificativas)
4. [Como executar](#4-como-executar)
5. [Usando a plataforma](#5-usando-a-plataforma)
6. [Motor de análise](#6-motor-de-análise)
7. [Módulo de IA](#7-módulo-de-ia)
8. [DevSecOps: Security Gate](#8-devsecops-security-gate)
9. [Dashboard](#9-dashboard)
10. [Estrutura do projeto](#10-estrutura-do-projeto)
11. [Decisões de projeto](#11-decisões-de-projeto)
12. [Limitações conhecidas e melhorias futuras](#12-limitações-conhecidas-e-melhorias-futuras)
13. [Ética e uso responsável](#13-ética-e-uso-responsável)
14. [Mapeamento com os critérios de avaliação](#14-mapeamento-com-os-critérios-de-avaliação)

---

## 1. Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| Parser AST | Transforma o código Python em árvore de sintaxe usando o módulo `ast` e a percorre com `ast.NodeVisitor` |
| Regras determinísticas | Detecta `eval`/`exec`, segredos hardcoded e `shell=True` em chamadas de subprocesso |
| Taint analysis | Rastreia dados não confiáveis (parâmetros e `input()`) até funções sensíveis, com reconhecimento de sanitização básica |
| Módulo de IA | LLM local classifica severidade, indica possível falso positivo, explica o risco e sugere correção |
| API REST | `POST /scan` recebe um arquivo `.py` e devolve as violações em JSON |
| Persistência | Cada violação é salva no PostgreSQL, formando o histórico usado pelo dashboard |
| Dashboard | Severidade, tendência de falhas, arquivos críticos e análise da IA |
| Security Gate | GitHub Actions executa o scanner a cada Pull Request e bloqueia o merge com falhas críticas |

---

## 2. Arquitetura

Os diagramas C4 (Contexto e Container) estão em [`docs/architecture-c4.md`](docs/architecture-c4.md).

Fluxo de um scan via API:

```mermaid
flowchart LR
    dev["Desenvolvedor"] -->|"POST /scan (.py)"| api["API FastAPI"]
    api -->|"scan_file()"| engine["Motor de análise<br/>AST + regras + taint"]
    api -->|"trecho + violação"| ai["Módulo de IA"]
    ai -->|"HTTP"| ollama["Ollama (LLM local)"]
    api -->|"SQLAlchemy"| db[("PostgreSQL")]
    db --> dash["Dashboard /dashboard"]
```

Fluxo no CI/CD:

```mermaid
flowchart LR
    pr["Pull Request"] --> gha["GitHub Actions"]
    gha --> cli["scan_ci.py<br/>(motor determinístico)"]
    cli -->|"violação crítica"| fail["Check falha: merge bloqueado"]
    cli -->|"sem violação crítica"| ok["Check passa: merge liberado"]
```

Containers (Docker Compose):

| Serviço | Imagem | Função |
|---|---|---|
| `api` | Build local (`python:3.11-slim`) | API FastAPI, motor de análise, cliente de IA e dashboard |
| `db` | `postgres:16` | Persistência do histórico de violações |

O Ollama roda **no host** (fora dos containers) e é acessado pela API via `host.docker.internal`.

---

## 3. Stack e justificativas

| Camada | Tecnologia | Por quê |
|---|---|---|
| Parsing | `ast` (biblioteca padrão) | AST nativa e completa para Python, sem dependências externas |
| API | FastAPI + Uvicorn | Rotas simples, validação automática e documentação em `/docs` |
| Banco | PostgreSQL + SQLAlchemy | Consultas agregadas para o dashboard; ORM evita SQL manual |
| IA | Ollama (`llama3.2:3b`) | LLM local: o código analisado não sai da máquina |
| Containerização | Docker + Docker Compose | Ambiente reproduzível com um comando |
| CI/CD | GitHub Actions | Integrado ao repositório; bloqueio de PR via checks obrigatórios |

---

## 4. Como executar

### Pré-requisitos

- Docker Desktop (Compose v2)
- [Ollama](https://ollama.com/download) instalado, com o modelo baixado:
  ```bash
  ollama pull llama3.2:3b
  ```
  O Ollama é necessário apenas para os scans **com IA**. Scans com `use_ai=false` funcionam sem ele.

### Passos

```bash
git clone https://github.com/wendelldsant/sast-devsecops-platform.git
cd sast-devsecops-platform

cp .env.example .env
```

Edite o `.env` e preencha os valores. Exemplo para desenvolvimento local:

```env
POSTGRES_USER=sast_user
POSTGRES_PASSWORD=defina_uma_senha
POSTGRES_DB=sast_db
DATABASE_URL=postgresql://sast_user:defina_uma_senha@db:5432/sast_db
OLLAMA_URL=http://host.docker.internal:11434
OLLAMA_MODEL=llama3.2:3b
```

A senha em `DATABASE_URL` deve ser igual à de `POSTGRES_PASSWORD`. O arquivo `.env` **não é versionado**.

```bash
docker compose up --build
```

| Recurso | URL |
|---|---|
| Documentação interativa da API | http://localhost:8000/docs |
| Health check | http://localhost:8000/health |
| Dashboard | http://localhost:8000/dashboard |

> Se a API não alcançar o Ollama (`Connection refused`), defina a variável de ambiente `OLLAMA_HOST=0.0.0.0` no sistema e reinicie o Ollama.

### Atualização de schema

`Base.metadata.create_all()` cria tabelas inexistentes, mas **não altera** tabelas já criadas. Em um banco criado antes da integração com IA, adicione as colunas manualmente:

```sql
ALTER TABLE scan_results
  ADD COLUMN ai_severity VARCHAR,
  ADD COLUMN ai_false_positive BOOLEAN,
  ADD COLUMN ai_explanation TEXT,
  ADD COLUMN ai_remediation TEXT;
```

---

## 5. Usando a plataforma

### Scan via API

```bash
# Com análise da IA (mais lento: uma chamada ao LLM por violação)
curl -X POST "http://localhost:8000/scan" -F "file=@tests/vulnerable_sample.py"

# Apenas motor determinístico (rápido)
curl -X POST "http://localhost:8000/scan?use_ai=false" -F "file=@tests/vulnerable_sample.py"
```

Exemplo de resposta (resumida):

```json
{
  "filename": "vulnerable_sample.py",
  "issues_found": 4,
  "issues": [
    {
      "rule_id": "DANGEROUS_FUNCTION",
      "cwe": "CWE-95",
      "message": "Uso perigoso de 'eval()' pode permitir execução de código arbitrário.",
      "line": 11,
      "severity": "critical",
      "ai_severity": "high",
      "ai_false_positive": false,
      "ai_explanation": "...",
      "ai_remediation": "..."
    }
  ]
}
```

### Scan via linha de comando (sem API, sem banco)

```bash
python scan_ci.py . --exclude tests --fail-on critical
```

Retorna código de saída `1` se houver violação na severidade informada ou acima, e `0` caso contrário. Gera o relatório `sast-report.json`.

### Consultar o histórico no banco

```bash
docker compose exec db psql -U sast_user -d sast_db \
  -c "SELECT filename, rule_id, severity, ai_severity, line FROM scan_results ORDER BY id DESC LIMIT 10;"
```

---

## 6. Motor de análise

O motor possui duas camadas complementares, implementadas sobre a mesma AST:

1. **Regras sintáticas** (`app/engine/rules.py`): padrões perigosos isolados.
2. **Taint analysis** (`app/engine/taint.py`): fluxo de dados não confiáveis até funções sensíveis.

As duas camadas podem sinalizar a mesma linha (por exemplo, um `eval(x)` com `x` vindo de parâmetro) por motivos diferentes: a primeira porque a função é perigosa por natureza, a segunda porque comprovou que a entrada não foi tratada.

### Regras

| Regra | CWE | Severidade | Detecta |
|---|---|---|---|
| `DANGEROUS_FUNCTION` | CWE-95 | critical | Chamadas a `eval()` e `exec()` |
| `HARDCODED_SECRET` | CWE-798 | high | Atribuição de string literal a variáveis como `password`, `senha`, `secret`, `api_key`, `token` |
| `SHELL_INJECTION` | CWE-78 | high | `run`/`call`/`Popen` com `shell=True` |
| `TAINTED_DATA_FLOW` | CWE-95 / CWE-78 | critical | Dado não confiável chegando a um *sink* sem sanitização |

### Taint analysis

- **Fontes (sources):** parâmetros da função e retorno de `input()`.
- **Destinos sensíveis (sinks):** `eval()`, `exec()`, `os.system()`, `os.popen()`.
- **Propagação:** atribuições simples entre variáveis (`b = a`).
- **Sanitização reconhecida:** conversão explícita de tipo (`int()`, `float()`, `bool()`). A variável deixa de ser considerada contaminada.
- **Escopo:** análise **intra-função**; cada função é analisada isoladamente.

---

## 7. Módulo de IA

Para cada violação, a API envia ao Ollama (`/api/generate`, `format: json`, `temperature: 0.1`) o trecho de código ao redor da linha suspeita (marcada com `>>>`) e recebe:

| Campo | Significado |
|---|---|
| `ai_severity` | Severidade segundo o LLM (`critical`, `high`, `medium`, `low`) |
| `ai_false_positive` | Se o LLM considera a violação um possível falso positivo |
| `ai_explanation` | Explicação curta do risco |
| `ai_remediation` | Sugestão de código corrigido |

Decisões relevantes:

- **Orientação por regra (`RULE_HINTS`):** cada tipo de violação recebe uma dica determinística de correção no prompt, o que reduz correções inventadas por um modelo pequeno.
- **Resiliência:** se o Ollama estiver indisponível, demorar além do timeout ou devolver JSON inválido, a análise de IA é descartada (e registrada em log) e o scan continua com os resultados das regras.
- **Saída do LLM tratada como dado não confiável:** o código analisado é de terceiros e pode tentar manipular o modelo (*prompt injection*). A severidade é validada contra uma lista fixa e a remediação é apenas armazenada como texto, nunca executada. No dashboard, todo texto é exibido com `textContent`.
- **Severidade da regra vs. severidade da IA:** ficam em colunas separadas. A decisão de bloqueio do Security Gate usa a severidade **das regras** (determinística e reproduzível); a da IA é informativa.

---

## 8. DevSecOps: Security Gate

Workflow: [`.github/workflows/security-gate.yml`](.github/workflows/security-gate.yml)

A cada Pull Request para a `main` (e a cada push na `main`):

1. O GitHub Actions faz o checkout e configura o Python 3.11.
2. Executa `python scan_ci.py . --exclude tests --fail-on critical`.
3. Se houver violação **crítica**, o job falha (`exit code 1`) e o check `sast-scan` fica vermelho.
4. Publica o relatório `sast-report.json` como artefato e um resumo em tabela na aba *Summary* do job.
5. As violações aparecem como **anotações nas linhas** do código, na aba *Files changed* do PR.

A `main` é protegida: o check `sast-scan` é **obrigatório**, então um PR com falha crítica não pode ser mesclado.

Escolhas de projeto:

- O CI usa apenas o motor determinístico (sem Ollama nem banco), por ser rápido e reproduzível, e porque o runner não tem o LLM local.
- O pipeline usa `permissions: contents: read` (princípio do menor privilégio).
- A pasta `tests/` é excluída do gate porque contém amostras vulneráveis **de propósito**, usadas para validar o scanner.

### Evidências

| Evidência | Arquivo |
|---|---|
| Gate aprovando código limpo | [08-gate-aprovado-log.png](docs/evidencias/08-gate-aprovado-log.png) |
| PR reprovado pelo gate | [01-gate-reprovado.png](docs/evidencias/01-gate-reprovado.png) |
| Log do scanner reprovando (`exit code 1`) | [02-gate-reprovado-log.png](docs/evidencias/02-gate-reprovado-log.png) |
| Merge bloqueado pelo check obrigatório | [03-gate-reprovado-merge-blocked.png](docs/evidencias/03-gate-reprovado-merge-blocked.png) |
| Anotações nas linhas do PR | [04](docs/evidencias/04-gate-reprovado-code-checks.png), [05](docs/evidencias/05-gate-reprovado-code-checks.png) |
| Regra de proteção da `main` | [06](docs/evidencias/06-branch-protection-rules.png), [06 (config)](docs/evidencias/06-branch-protection-rules-config.png), [07 (config)](docs/evidencias/07-branch-protection-rules-config.png) |

---

## 9. Dashboard

Acesse `http://localhost:8000/dashboard`. Dados vêm de `GET /api/dashboard/summary`.

- Indicadores gerais: total de violações, críticas, arquivos analisados e possíveis falsos positivos segundo a IA.
- Distribuição por severidade.
- Tendência de falhas por semana.
- Top 5 arquivos com mais violações.
- Últimas violações, com a análise da IA expandível.

Implementado em HTML, CSS e SVG puros, sem dependências externas (funciona offline).

![Dashboard: visão geral](docs/evidencias/09-dashboard-visao-geral.png)
![Dashboard: análise da IA](docs/evidencias/11-dashboard-analise-ia.png)

Para popular o dashboard com dados de exemplo:

```bash
for f in tests/*.py; do
  curl -s -X POST "http://localhost:8000/scan?use_ai=false" -F "file=@$f" > /dev/null
done
```

---

## 10. Estrutura do projeto

```
sast-devsecops-platform/
├── app/
│   ├── api/
│   │   ├── main.py            # rotas /health e /scan
│   │   ├── dashboard.py       # rotas /dashboard e /api/dashboard/summary
│   │   ├── database.py        # conexão e sessão SQLAlchemy
│   │   ├── models.py          # tabela scan_results
│   │   └── static/dashboard.html
│   ├── engine/
│   │   ├── parser.py          # orquestra o scan de um arquivo
│   │   ├── rules.py           # regras sintáticas (NodeVisitor)
│   │   └── taint.py           # taint analysis intra-função
│   └── ai/
│       └── ollama_client.py   # integração com o LLM local
├── tests/                     # amostras vulneráveis (fixtures)
├── docs/
│   ├── architecture-c4.md     # diagramas C4
│   └── evidencias/            # prints do Security Gate e do dashboard
├── .github/workflows/security-gate.yml
├── scan_ci.py                 # CLI do Security Gate
├── scan_cli.py                # execução local simples do motor
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## 11. Decisões de projeto

| Decisão | Motivo |
|---|---|
| Linguagem-alvo única (Python) com `ast` nativo | Reduz o escopo e concentra esforço em precisão (menos falsos positivos). O parser está desacoplado das regras |
| Sem Redis/Celery no MVP | Processamento síncrono é suficiente para o escopo; filas ficam como melhoria futura |
| Duas camadas de detecção (regras + taint) | Regras pegam padrões perigosos; taint comprova se a entrada realmente chega ao ponto sensível |
| Credenciais fora do versionamento (`.env`) | Evita o problema que a própria plataforma detecta (CWE-798) |
| Gate baseado em regras, IA apenas informativa | Decisão de bloqueio determinística e auditável |
| Histórico por violação (uma linha por achado) | Facilita agregações do dashboard |

---

## 12. Limitações conhecidas e melhorias futuras

**Limitações**

- **Multilinguagem:** o motor analisa apenas Python. O parser foi mantido desacoplado das regras para permitir a futura substituição por **Tree-sitter**, viabilizando JavaScript e Java sem reescrever as regras.
- **Taint analysis simplificada:** é intra-função (não rastreia dados entre funções ou módulos) e só considera como sink argumentos que são variáveis simples (não expressões como concatenações ou f-strings). Funções `async def` e parâmetros *keyword-only* não são analisados pela taint analysis.
- **Heurística de segredos:** baseada no nome da variável; não detecta segredos em variáveis com nomes genéricos nem por entropia.
- **Cobertura de regras:** três padrões de regra mais o fluxo de taint. Injeção de SQL, desserialização insegura e criptografia fraca não estão cobertas.
- **Qualidade da IA:** o modelo `llama3.2:3b` acerta o diagnóstico, mas as correções sugeridas nem sempre são válidas. Devem ser tratadas como **sugestão para revisão humana**.
- **Desempenho:** a chamada ao LLM é síncrona e feita por violação; em CPU, scans com muitas violações são lentos.
- **Migrações de banco:** manuais.

**Melhorias futuras**

- Processamento assíncrono com Redis + Celery.
- Taint analysis interprocedural e reconhecimento de mais sources/sinks (frameworks web, SQL).
- Suporte a outras linguagens via Tree-sitter.
- Modelos maiores (basta alterar `OLLAMA_MODEL`).
- Migrações com Alembic.
- Autenticação nos endpoints da API.

---

## 13. Ética e uso responsável

A análise de código deve respeitar a propriedade intelectual e a privacidade do código-fonte. Neste projeto:

- Os arquivos em `tests/` são **amostras sintéticas** criadas para validar o scanner; não pertencem a terceiros.
- O uso do LLM é **local**: nenhum código analisado é enviado a serviços externos.
- A plataforma deve ser usada apenas em repositórios próprios, autorizados ou de código aberto.
- O objetivo é auxiliar o desenvolvedor na melhoria contínua da segurança.

---

## 14. Mapeamento com os critérios de avaliação

| Critério | Peso | Onde está atendido |
|---|---|---|
| Arquitetura | 25% | Seções 2, 3, 10 e 11; `docs/architecture-c4.md`; Docker Compose; separação em `engine`, `ai` e `api` |
| Robustez SAST | 30% | Seção 6; AST via `NodeVisitor`; taint analysis com sanitização; duas camadas de detecção |
| Inovação IA | 20% | Seção 7; LLM local, classificação, falso positivo, remediação, `RULE_HINTS`, tratamento da saída como dado não confiável |
| DevSecOps | 15% | Seção 8; Security Gate com check obrigatório, anotações no PR, relatório e resumo no job |
| Defesa | 10% | Seções 11 e 12 (decisões e análise crítica); roteiro de apresentação |