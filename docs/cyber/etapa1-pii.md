# Etapa 1: Mapeamento de PII (GS CitizenTech, Cybersecurity)

Módulo `app/pii/` e regra `PII_HARDCODED` no motor SAST. Todos os dados de teste são fictícios.

## Tipos, base legal e peso
| Tipo | Categoria | Peso (Risco Cidadão) | Severidade | CWE |
|---|---|---|---|---|
| SAUDE | sensível (LGPD art. 5, II) | 3 | critical | CWE-359 |
| SENHA | credencial | 3 | high | CWE-798 |
| CPF | pessoal comum (art. 5, I) | 2 | high | CWE-359 |
| TELEFONE | pessoal comum | 1 | medium | CWE-359 |
| EMAIL | pessoal comum | 1 | medium | CWE-359 |

## Como cada detector decide (e por quê)
- **CPF:** padrão com ou sem máscara + dígito verificador (módulo 11) + rejeição de 11 dígitos iguais.
  Confiança alta com máscara ou com a palavra "cpf" antes; média com 11 dígitos soltos. O dígito
  verificador elimina cerca de 99% dos números aleatórios (protocolos, por exemplo).
- **Telefone:** DDD brasileiro válido + celular (9 + 8 dígitos) ou fixo (2 a 5 + 7 dígitos). Formatado = alta.
  Só dígitos exige palavra de contexto (tel, whats, cel...), senão é ignorado: reduz falso positivo em protocolos.
- **E-mail:** padrão usual, confiança alta.
- **Senha:** palavra-chave (senha, password, token...) + separador (`:`, `=`, `é`) + valor. Só o valor é mascarado.
- **Saúde:** léxico de condições + marcador de contexto pessoal ("tenho", "faz tratamento de"...), mais códigos CID.
  Ficam de fora de propósito "dengue" (queixa de saúde pública sobre um foco no bairro) e
  "cadeirante/deficiência" (relatos de acessibilidade da calçada). Os dois gerariam muito falso positivo na Zeladoria.

## Falso positivo x falso negativo
Escolhemos precisão antes de cobertura para evitar alerta em excesso (o morador e o agente deixariam de confiar).
Cada achado carrega confiança alta ou média, e o dashboard separa certeza de suspeita.

Limitações conhecidas (declaradas em `scripts/validar_pii.py`): "minha senha 1234" (sem separador),
condições de saúde sem marcador de contexto, telefone sem DDD e CPF ofuscado com espaços entre todos os dígitos.

## Regras de projeto
1. O módulo nunca guarda nem devolve o valor encontrado, só a posição. O relatório do scanner não pode virar um vazamento.
2. Em literais de código só entram CPF, e-mail, telefone e senha (alta precisão). Saúde é tratada no modo texto (ocorrências).
3. Docstrings não são analisadas.
4. `mask_pii()` é o sanitizador do projeto e é idempotente (reanalisar texto mascarado não gera achados).

## Como validar
```
python -m pytest tests/test_pii.py -v
python scripts/validar_pii.py
python scan_ci.py . --exclude tests --exclude scripts/validar_pii.py --fail-on critical
```
