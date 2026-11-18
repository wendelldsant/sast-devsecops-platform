# Etapa 3: Tradução via IA em alertas ao cidadão (GS CitizenTech, Cybersecurity)

`app/ai/citizen_alert.py` transforma cada achado técnico do SAST em um alerta claro de risco real
para o morador. Pontos de exposição em `app/risk.py`. LLM local (Ollama, `llama3.2:3b`).

## Fluxo
achado do SAST → pontos de exposição (regra) → prompt só com categorias → Ollama (JSON schema) →
validação → alerta (fonte `ia`) ou alerta-padrão (fonte `padrao`) → API e banco.

## Decisões e justificativas
- **O LLM escreve; a regra decide o número.** Nível e pontos (peso do tipo de PII x peso do destino, 1 a 9)
  vêm de `risk.py`. Um modelo de 3B pode errar a gravidade, e o indicador precisa ser reproduzível e defensável.
- **Privacidade no prompt.** O prompt tem só categorias ("o seu CPF foi parar em um arquivo sem proteção").
  Sem trecho de código, sem nome de variável, sem valor. Na API, achados de PII nunca enviam o trecho de código
  ao LLM, porque a linha pode conter a própria PII.
- **Saída restrita e validada.** O `format` do Ollama recebe um JSON schema (com retentativa em `"json"` para
  versões antigas). Depois a resposta é validada: chaves, tamanho, jargão (CWE, taint, SAST) e **ausência de PII**
  (a saída do LLM passa pelo detector da Etapa 1).
- **Consistência com o achado.** Num teste real com o `llama3.2:3b`, o modelo descreveu um vazamento na
  resposta da API como "arquivo" e escreveu "Seu dados" em outro alerta. Passamos a exigir que o texto cite o
  dado e o destino reais e nenhum outro lugar; o que não bater é descartado e entra o alerta-padrão. O prompt
  também ganhou dois exemplos com destinos diferentes, para o modelo não copiar o exemplo.
- **Cache por categoria.** O alerta depende do tipo de PII e do destino, não da ocorrência. Só o que veio da IA
  e passou na validação é guardado, então repetir a mesma categoria não chama o LLM de novo (cada chamada levou
  de 16 a 41 s em CPU).
- **Sempre há alerta.** Se o Ollama estiver fora do ar, demorar ou devolver algo inválido, entra o alerta-padrão
  determinístico. O campo `fonte` (`ia` ou `padrao`) vai para o banco e para o dashboard.
- **Migração idempotente.** `ensure_columns()` adiciona as colunas novas em `scan_results` na subida da API
  (`pii_type`, `sink`, `confidence`, `alert_*`), sem `ALTER TABLE` manual.

## Pontos de exposição
| Tipo de PII | Peso | Destino | Peso |
|---|---|---|---|
| SAUDE, SENHA, MULTIPLOS | 3 | resposta da API, exceção | 3 |
| CPF, TEXTO_LIVRE | 2 | arquivo, código (PII fixa) | 2 |
| TELEFONE, EMAIL | 1 | log, print | 1 |

Níveis: 7 a 9 crítico, 4 a 6 alto, 2 a 3 médio, 1 baixo. Exemplos: senha em exceção = 9 (crítico);
CPF na resposta da API = 6 (alto); telefone em print = 1 (baixo).

## Limitações
- O texto do alerta depende da qualidade do modelo de 3B; a validação descarta o que sair do padrão, mas não corrige erros de gramática. Um modelo maior (`OLLAMA_MODEL`) melhora o texto.
- Os pesos são uma convenção do projeto, justificada pela LGPD (dado sensível pesa mais) e pelo alcance do destino.
- O alerta é gerado por categoria, não por ocorrência específica do morador.

## Como validar
```
pip install -r requirements-dev.txt
python -m pytest tests -v
python scripts/alertas_prototipo.py --saida docs/cyber/evidencias/etapa3-alertas.txt
```
