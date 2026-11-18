# Etapa 4: Dashboard executivo e indicador Risco Cidadão (GS CitizenTech, Cybersecurity)

O dashboard do SAST ganhou a seção **Risco Cidadão** (`/dashboard`) e o endpoint `/api/dashboard/citizen-risk`.

## O indicador
```
pontos do achado = peso do tipo de PII  x  peso do destino  x  peso da confiança
Risco Cidadão    = mín(100, soma dos pontos ÷ 30 x 100)
```
| Tipo de PII | Peso | Destino | Peso | Confiança | Peso |
|---|---|---|---|---|---|
| SAUDE, SENHA, MULTIPLOS | 3 | resposta da API, exceção | 3 | alta | 1,0 |
| CPF, TEXTO_LIVRE | 2 | arquivo, código (PII fixa) | 2 | média | 0,5 |
| TELEFONE, EMAIL | 1 | log, print | 1 | | |

Níveis: 0 sem exposição · 1 a 24 baixo · 25 a 49 médio · 50 a 74 alto · 75 a 100 crítico.
Os 30 pontos máximos podem ser ajustados com `RISCO_PONTOS_MAXIMOS`.

Resultado no protótipo da Zeladoria: vulnerável = **87** (26 pontos), correção parcial = **50** (15 pontos), corrigido = **0**.

## Decisões e justificativas
- **Estado atual, não histórico acumulado.** O indicador usa só o último scan de cada arquivo. Se somasse todo o
  histórico, corrigir o código nunca reduziria o risco.
- **Tabela `scan_runs`.** Cada `/scan` registra uma execução, mesmo com 0 achados. Sem isso, o arquivo corrigido
  não deixaria nenhuma linha e o risco ficaria preso no valor antigo. Também alimenta o gráfico de evolução por scan.
- **Escala linear com teto.** É simples de explicar e auditar: 30 pontos ponderados (por exemplo, 3 vazamentos de
  9 pontos) já são o risco máximo. Os pesos seguem a LGPD (dado sensível pesa mais) e o alcance do destino
  (resposta da API é visível a qualquer cliente; log só a quem tem acesso interno).
- **Confiança média vale metade.** O taint que passou por função desconhecida é suspeita, não certeza.
- **Alertas ao cidadão na tabela de maiores riscos**, com a fonte (IA ou padrão), para mostrar o resultado da Etapa 3.
- **Segurança do próprio painel.** Todo texto vindo da API entra na página com `textContent`, nunca com `innerHTML`
  (nomes de arquivo e mensagens vêm de uploads de terceiros), e nenhum valor de PII chega ao dashboard.

## Limitações
- Os pesos são uma convenção do projeto, não um padrão externo.
- O indicador mede a exposição encontrada pelo SAST; não mede vazamentos reais em produção.
- O painel não tem autenticação (como o dashboard original do SAST).

## Como validar
```
python -m pytest tests -v
docker compose up --build            # em outro terminal
python scripts/popular_dashboard.py  # envia vulnerável -> parcial -> corrigido
# abrir http://localhost:8000/dashboard
```
