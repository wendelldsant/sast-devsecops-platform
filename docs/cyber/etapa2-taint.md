# Etapa 2: Taint analysis de PII (GS CitizenTech, Cybersecurity)

Regra `PII_LEAK` em `app/engine/pii_taint.py`. Rastreia dado pessoal da fonte até saídas inseguras.
Protótipo auditado: `tests/prototipo_zeladoria/` (`vulneravel.py` e `corrigido.py`). Dados fictícios.

## Modelo
| Conceito | Definição neste projeto |
|---|---|
| Fonte (source) | Parâmetro, atributo, chave ou `.get()` com nome do vocabulário da Zeladoria: cpf, telefone, celular, email, senha, password, token, descricao, endereco, observacao, saude, laudo. Objeto de corpo (`ocorrencia`, `dados`, tipos `*In`) vale como "objeto completo". |
| Propagação | Atribuição, f-string, `+`, `%`, `.format()`, dict, lista, desempacotamento, loop, comprehension e chamadas. |
| Sink | log (`logger.*`, `logging.*`), `print`, escrita em arquivo (`.write`, `json.dump`), exceção (`raise`, `HTTPException`) e `return` de rota FastAPI. |
| Sanitizador | `mask_pii()` e `len()`. |

| Destino | CWE | Peso do destino (Risco Cidadão) |
|---|---|---|
| log, print | CWE-532 | 1 |
| arquivo | CWE-312 | 2 |
| exceção | CWE-209 | 3 |
| resposta da API | CWE-200 | 3 |

Severidade do `PII_LEAK`: sempre `critical`, porque é um fluxo confirmado, sem sanitização, até uma saída insegura.
Por isso o Security Gate bloqueia o PR. O risco relativo entre vazamentos vem do peso do tipo de PII e do destino.

## Decisões e justificativas
- **Fonte pelo nome do campo.** A análise estática não vê o conteúdo do dado. Declarar o vocabulário é transparente e testável. Limite assumido: campo com outro nome não é fonte.
- **Propagação conservadora.** Chamada desconhecida repassa o taint, mas com confiança `media` (conversões de texto como `str()` e `.strip()` mantêm `alta`). Para privacidade, alerta a mais é melhor que vazamento escondido, e o nível de confiança deixa o dashboard separar certeza de suspeita.
- **`return` só é sink em rota HTTP** (decorador `@app.get/post/...`). Em função comum o retorno vai para outro código da aplicação, que a análise intra-função não enxerga.
- **Fluxo condicional.** `if`, `try` e loops são analisados com cópia do estado e unidos depois (se qualquer ramo contamina, o taint segue).
- **Reatribuição com valor limpo remove o taint** (`x = o.cpf; x = "ok"`), o que evita falso positivo.
- **O relatório mostra o fluxo, nunca o valor**: `ocorrencia.telefone (L31) → contato (L31) → print() (L32)`.

## Limitações conhecidas
Análise intra-função (um helper que devolve PII só é visto onde é usado); logger com nome fora da lista
(`logger`, `log`, `logging`, `LOGGER`...) não é reconhecido; `response_model` do FastAPI não é modelado
(a rota que filtra campos por `response_model` ainda aparece como achado); alias de função e `getattr` não são seguidos.

## Como validar
```
python -m pytest tests -v
python scripts/auditar_prototipo.py
python scan_ci.py tests/prototipo_zeladoria/vulneravel.py --fail-on critical   # REPROVADO (5 bloqueantes)
python scan_ci.py tests/prototipo_zeladoria/corrigido.py --fail-on critical    # APROVADO
```
