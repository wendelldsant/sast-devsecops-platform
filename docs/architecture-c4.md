# Arquitetura da Plataforma SAST

Este documento descreve a arquitetura técnica da plataforma, seguindo o C4 Model em dois níveis: Contexto (visão externa) e Container (visão interna dos componentes). Os diagramas refletem o estado real da implementação até o CP1, com os componentes planejados para os próximos checkpoints sinalizados explicitamente.

## Nível 1 — Diagrama de Contexto

Mostra quem interage com o sistema e com quais serviços externos ele se conecta.

```mermaid
flowchart TB
    dev["👤 Desenvolvedor<br/>Envia código-fonte para análise"]
    sast["🛡️ Plataforma SAST<br/>Analisa código, detecta vulnerabilidades<br/>e sugere correções"]
    llm["🤖 Ollama (LLM Local)<br/>Classifica severidade e sugere remediação<br/><i>[Planejado - CP2]</i>"]
    gha["⚙️ GitHub Actions<br/>Executa análise em pipelines CI/CD<br/><i>[Planejado - CP3]</i>"]

    dev -->|"Envia arquivo .py (HTTPS)"| sast
    sast -->|"Consulta classificação semântica (HTTP)"| llm
    gha -->|"Aciona scan automático em Pull Requests (HTTPS)"| sast
```

## Nível 2 — Diagrama de Container

Mostra os componentes internos da plataforma, como eles se comunicam, e como estão organizados em containers Docker.

```mermaid
flowchart TB
    dev["👤 Desenvolvedor"]

    subgraph docker["🐳 Docker Compose"]
        subgraph apiContainer["Container: api"]
            api["API<br/>FastAPI / Python<br/>Recebe arquivos, orquestra a<br/>análise e expõe endpoints REST"]
            engine["Motor de Análise<br/>Python ast module<br/>Percorre a AST e aplica<br/>regras de detecção"]
            ai["Módulo de IA<br/>Python + Ollama Client<br/><i>[Planejado - CP2]</i>"]
        end
        subgraph dbContainer["Container: db"]
            db[("Banco de Dados<br/>PostgreSQL<br/>Armazena histórico<br/>de violações")]
        end
    end

    llm["🤖 Ollama (LLM Local)<br/><i>Serviço externo</i>"]

    dev -->|"POST /scan (upload de arquivo)"| api
    api -->|"Chama scan_file()"| engine
    api -->|"Insere resultados via SQLAlchemy (SQL)"| db
    engine -->|"Envia trechos suspeitos"| ai
    ai -->|"Solicita classificação/sugestão (HTTP API)"| llm
```

**Nota sobre containerização**: os componentes `api` (API + Motor de Análise + Módulo de IA) e `db` (PostgreSQL) representados acima rodam em containers Docker isolados, orquestrados via `docker-compose.yml`. Cada container tem suas próprias dependências e ciclo de vida, comunicando-se através da rede interna do Docker Compose (os serviços se referenciam pelo nome, ex: `db`, não por `localhost`).

## Status de implementação

| Componente | Status |
|---|---|
| API (FastAPI) | ✅ Implementado (CP1) |
| Motor de Análise (AST) | ✅ Implementado (CP1) |
| Banco de Dados (PostgreSQL) | ✅ Implementado (CP1) |
| Containerização (Docker Compose) | ✅ Implementado (CP1) |
| Módulo de IA (Ollama) | 🔜 Planejado (CP2) |
| Integração CI/CD (GitHub Actions) | 🔜 Planejado (CP3) |

## Decisão de escopo: linguagem única (Python)

O motor de análise foi implementado com o módulo `ast` nativo do Python para a linguagem-alvo escolhida. A arquitetura foi desenhada de forma modular (parser desacoplado das regras) para permitir a futura substituição por Tree-sitter, viabilizando suporte a múltiplas linguagens sem reescrever o motor de regras.