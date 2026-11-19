# Entrega de Cybersecurity: Zeladoria do Bairro (GS CitizenTech 2026.2, FIAP)

Engenharia de Software, 3º ano, FIAP Paulista. Entrega via Teams até 19/11/2026, 23h55.

**Integrantes:** Augusto Rocha Silva - RM556316 |
Erik Yuuta Goto - RM558076 |
Guilherme Vieira Augusto - RM557264 |
Wendell dos Santos Silva - RM558859

## A solução e onde a Cybersecurity entra
- **Cidadão beneficiado:** o morador que registra problemas do bairro no app Zeladoria do Bairro.
- **Problema desta entrega:** ao digitar texto livre (descrição, endereço, telefone), o morador pode incluir CPF, telefone,
  senha ou dado de saúde. Se o sistema grava esse dado em log, arquivo, mensagem de erro ou resposta da API, ele vaza.
- **O que construímos:** estendemos nossa Plataforma SAST & DevSecOps (Projeto Integrador, Python) com um módulo que
  **detecta PII**, **rastreia o fluxo do dado até saídas inseguras (taint analysis)**, **traduz cada falha em alerta
  claro ao cidadão (IA local)** e **mede o risco no dashboard (Risco Cidadão)**.
- **ODS:** 11 (cidades e comunidades sustentáveis) e 9 (indústria, inovação e infraestrutura).
- **Dados:** 100% fictícios. Nenhum dado pessoal real foi usado.

## Mapa da pontuação (10,0 pontos)
| Critério | Pontos | O que entregamos | Onde está | Como verificar |
|---|---|---|---|---|
| Robustez do motor de parsing PII | 3,0 | Detectores de CPF (dígito verificador), telefone, e-mail, senha e saúde, com confiança; regra `PII_HARDCODED`; mascaramento | `app/pii/`, `app/engine/rules.py`, `tests/test_pii.py`, `docs/cyber/etapa1-pii.md` | `python scripts/validar_pii.py` |
| Eficácia do Taint Analysis | 3,0 | Regra `PII_LEAK`: fonte → propagação → sink, com sanitizador `mask_pii()` e o fluxo no relatório | `app/engine/pii_taint.py`, `tests/test_pii_taint.py`, `tests/prototipo_zeladoria/`, `docs/cyber/etapa2-taint.md` | `python scripts/auditar_prototipo.py` |
| Inovação com IA na remediação | 2,0 | Alerta ao cidadão escrito pelo Ollama, com validação de coerência e alerta-padrão de segurança | `app/ai/citizen_alert.py`, `docs/cyber/etapa3-ia.md` | `python scripts/alertas_prototipo.py` |
| Dashboard Executivo (Risco Cidadão) | 2,0 | Indicador 0 a 100, exposição por tipo e destino, evolução por scan, tabela de alertas | `app/risk.py`, `app/api/dashboard.py`, `app/api/static/dashboard.html`, `docs/cyber/etapa4-dashboard.md` | `python scripts/popular_dashboard.py` e abrir `/dashboard` |

## Entregáveis do briefing
| Entregável | Onde |
|---|---|
| Código do novo módulo (regras PII) | Este ZIP: `app/pii/`, `app/engine/pii_taint.py`, `app/engine/rules.py` |
| Auditoria do protótipo (evidências do taint em ação) | `docs/cyber/evidencias/etapa2-auditoria.txt` e os prints em `docs/cyber/evidencias/` |
| Dashboard atualizado (vídeo e print do painel gerando o Risco Cidadão) | Prints `01` a `12` e arquivos `.txt` em `docs/cyber/evidencias/` e vídeo (link): 

## Resultados
- **Testes:** 120 automatizados (PII, taint, alertas, API e dashboard), todos passando.
- **Auditoria do protótipo da Zeladoria:** versão vulnerável = 5 vazamentos de PII (log, print, arquivo, resposta da API e exceção)
  e 1 CPF fixo no código; versão corrigida = 0.
- **Risco Cidadão:** vulnerável **87** (crítico), correção parcial **50** (alto), corrigido **0** (sem exposição).
- **Security Gate (GitHub Actions):** reprova o PR que vaza PII (regra `PII_LEAK` é `critical`).

## Como reproduzir
```
pip install -r requirements-dev.txt
python -m pytest tests -v
python scripts/validar_pii.py
python scripts/auditar_prototipo.py
python scan_ci.py tests/prototipo_zeladoria/vulneravel.py --fail-on critical   # reprova (5 bloqueantes)
python scan_ci.py tests/prototipo_zeladoria/corrigido.py --fail-on critical    # aprova
```
Dashboard e alertas com IA (requer Docker e Ollama com `llama3.2:3b`; copie `.env.example` para `.env`):
```
docker compose up --build
python scripts/popular_dashboard.py          # com --ia para alertas escritos pelo Ollama
# abrir http://localhost:8000/dashboard
```

## Decisões de projeto
- **Precisão antes de cobertura na detecção de PII:** CPF só vale com dígito verificador; telefone só com DDD e, sem
  formatação, só com palavra de contexto; "dengue" e "cadeirante" ficam de fora (relatos do bairro, não dado de uma pessoa).
- **Taint com fonte pelo nome do campo e propagação conservadora:** alerta a mais é melhor que vazamento escondido; a
  confiança (alta ou média) separa certeza de suspeita.
- **O LLM escreve, a regra decide o número:** o nível de risco vem de pesos determinísticos; o prompt só tem categorias
  (nunca código ou valores); a resposta do modelo é validada e, se falhar, entra o alerta-padrão.
- **Risco Cidadão sobre o estado atual:** só o último scan de cada arquivo conta, e cada scan é registrado mesmo sem achados.
- **O próprio relatório não vaza PII:** achados mostram o fluxo (nomes de campos e variáveis), nunca o valor.

## Limitações assumidas
- A fonte do taint é detectada pelo nome do campo; análise intra-função; `response_model` do FastAPI não é modelado.
- A detecção de saúde é heurística (léxico com contexto) e foi validada em um conjunto pequeno e controlado.
- O modelo local de 3B errou destino e gênero em teste real; por isso há validação e alerta-padrão.
- Os pesos do Risco Cidadão são uma convenção do projeto, justificada pela LGPD e pelo alcance de cada destino.

## Uso de IA
IA como copiloto (Claude) para planejar, revisar e escrever código e documentação; todos os prompts estão em
[`prompts.md`](prompts.md). No produto, o LLM local (Ollama) só escreve o texto dos alertas ao cidadão.
