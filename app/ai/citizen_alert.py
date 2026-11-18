"""Tradução de falhas técnicas em alertas claros de risco real ao cidadão (Etapa 3).

Garantias de projeto (ver docs/cyber/etapa3-ia.md):
- Privacidade: o prompt tem só categorias (tipo de dado e destino), nunca trecho de código,
  nome de variável ou valor. Mesmo com o LLM local, a PII não entra no prompt.
- Quem decide o risco é a regra determinística (app/risk.py); o LLM só escreve o texto.
- A saída do LLM é validada (formato, tamanho, jargão e PII). Se falhar, entra o alerta-padrão.
  Por isso todo achado sempre tem alerta, com ou sem Ollama.
"""
import json
import logging

import requests

from app.ai.ollama_client import OLLAMA_MODEL, OLLAMA_TIMEOUT, OLLAMA_URL
from app.pii import find_pii
from app.risk import exposure_points, risk_level

logger = logging.getLogger("citizen_alert")

DADO = {
    "CPF": "o seu CPF", "TELEFONE": "o seu telefone", "EMAIL": "o seu e-mail",
    "SENHA": "a sua senha", "SAUDE": "as suas informações de saúde",
    "TEXTO_LIVRE": "o texto que você escreveu (que pode conter dados pessoais)",
    "MULTIPLOS": "vários dos seus dados pessoais",
}
TITULO = {
    "CPF": "Seu CPF pode ficar exposto", "TELEFONE": "Seu telefone pode ficar exposto",
    "EMAIL": "Seu e-mail pode ficar exposto", "SENHA": "Sua senha pode ficar exposta",
    "SAUDE": "Suas informações de saúde podem ficar expostas",
    "TEXTO_LIVRE": "Dados pessoais no seu texto podem ficar expostos",
    "MULTIPLOS": "Vários dados seus podem ficar expostos",
}
RISCO_TIPO = {
    "CPF": "golpes e fraudes feitos em seu nome",
    "TELEFONE": "ligações e mensagens de golpistas",
    "EMAIL": "e-mails falsos (phishing) e spam",
    "SENHA": "alguém entrar na sua conta e se passar por você",
    "SAUDE": "a sua condição de saúde ser conhecida sem a sua vontade, o que pode causar constrangimento ou discriminação",
    "TEXTO_LIVRE": "dados pessoais digitados no texto serem vistos por quem não deveria",
    "MULTIPLOS": "golpes e uso indevido de vários dados seus ao mesmo tempo",
}
DESTINO = {
    "log": "em um registro interno do sistema, que outras pessoas e sistemas podem ler",
    "print": "em um registro interno do sistema, que outras pessoas e sistemas podem ler",
    "arquivo": "em um arquivo de texto sem proteção",
    "excecao": "em uma mensagem de erro exibida na tela",
    "resposta_api": "na resposta enviada ao aplicativo, que pode ser lida por qualquer pessoa",
    "codigo": "no código do sistema, que fica guardado e compartilhado entre desenvolvedores",
}
# Falhas que não são de PII (regras do SAST original): título, risco e ação em linguagem simples
REGRA_SIMPLES = {
    "HARDCODED_SECRET": ("Uma chave de acesso está escrita no código",
                         "Quem ler o código pode usar essa chave para entrar em sistemas e ver dados dos moradores.",
                         "A equipe deve guardar a chave fora do código e trocá-la."),
    "DANGEROUS_FUNCTION": ("O sistema pode ser induzido a executar comandos",
                           "Um invasor poderia fazer o sistema executar ações indevidas e acessar dados dos moradores.",
                           "A equipe deve trocar esse trecho por uma alternativa segura."),
    "SHELL_INJECTION": ("O sistema pode ser induzido a executar comandos",
                        "Um invasor poderia usar um texto digitado para controlar o computador do sistema.",
                        "A equipe deve impedir que texto digitado vire comando."),
    "TAINTED_DATA_FLOW": ("Texto digitado chega a uma função perigosa",
                          "Um invasor poderia digitar algo capaz de alterar o funcionamento do sistema.",
                          "A equipe deve validar o que é digitado antes de usar."),
}
JARGAO_PROIBIDO = {"cwe", "taint", "sast", "stack trace"}

# Consistência com o achado: o texto do LLM precisa falar do dado e do destino REAIS.
# (Num teste real, um modelo de 3B disse "arquivo" para um vazamento na resposta da API.)
DESTINO_TERMOS = {
    "log": ("registro",), "print": ("registro",), "arquivo": ("arquivo",),
    "excecao": ("erro", "mensagem"), "resposta_api": ("resposta", "aplicativo"),
    "codigo": ("código", "codigo"),
}
LOCAIS_EXCLUSIVOS = ("arquivo", "registro", "código", "codigo")  # só valem se forem o destino real
DADO_TERMOS = {
    "CPF": ("cpf",), "TELEFONE": ("telefone",), "EMAIL": ("e-mail", "email"), "SENHA": ("senha",),
    "SAUDE": ("saúde", "saude"), "TEXTO_LIVRE": ("texto", "dados pessoais"), "MULTIPLOS": ("dados",),
}
# Consequências que o modelo costuma inventar e que não decorrem do achado
INVENTADOS = ("transações", "transacoes", "data de nascimento", "cartão", "cartao",
              "conta bancária", "conta bancaria", "crédito", "credito", "empréstimo", "emprestimo")
_CACHE: dict = {}  # alerta por categoria (regra, tipo, destino): só guarda o que veio da IA

PROMPT = """Você escreve alertas de segurança para moradores comuns, em português do Brasil, com linguagem simples.

Fato técnico já verificado: {fato}
Escreva um alerta curto para o morador que usa o aplicativo "Zeladoria do Bairro".

Regras:
- Fale do dado e do lugar EXATAMENTE como no fato. Não cite outros lugares.
- Frases curtas, sem termos técnicos (nada de log, API, CWE, código, servidor).
- Diga o risco real para a pessoa e o que a equipe vai fazer.
- Não invente números, nomes, datas nem consequências específicas (contas, cartões, transações).
- Não escreva CPF, telefone, e-mail nem senha.

Responda SOMENTE com um JSON com as chaves:
"risco" (até 2 frases) e "o_que_fazer" (até 2 frases).

Exemplo 1
Fato: o telefone do morador foi parar na resposta enviada ao aplicativo.
{{"risco": "Seu telefone foi enviado na resposta do aplicativo. Quem vir essa resposta poderia usá-lo para golpes por ligação ou mensagem.", "o_que_fazer": "A equipe vai impedir que o telefone seja enviado assim. Desconfie de contatos inesperados."}}

Exemplo 2
Fato: o e-mail do morador foi parar em um registro interno do sistema.
{{"risco": "Seu e-mail ficou em um registro interno do sistema. Quem tiver acesso poderia usá-lo para enviar e-mails falsos.", "o_que_fazer": "A equipe vai ocultar o e-mail nesses registros. Desconfie de mensagens inesperadas."}}
"""

ALERT_SCHEMA = {
    "type": "object",
    "properties": {"risco": {"type": "string"}, "o_que_fazer": {"type": "string"}},
    "required": ["risco", "o_que_fazer"],
}


def _facts(issue: dict) -> str:
    """Descreve o achado só por categorias, em linguagem simples. Nunca inclui código nem valores."""
    pii_type = issue.get("pii_type")
    if pii_type in DADO:
        destino = DESTINO.get(issue.get("sink") or "codigo", DESTINO["codigo"])
        return f"{DADO[pii_type]} (dado de um morador) foi parar {destino}, sem proteção."
    return REGRA_SIMPLES.get(issue["rule_id"], ("Falha de segurança", "", ""))[0] + "."


def build_prompt(issue: dict) -> str:
    return PROMPT.format(fato=_facts(issue))


def default_alert(issue: dict) -> dict:
    """Alerta determinístico, usado quando o LLM falha ou está desligado."""
    pii_type = issue.get("pii_type")
    if pii_type in DADO:
        destino = DESTINO.get(issue.get("sink") or "codigo", DESTINO["codigo"])
        acao = "A equipe do sistema deve ocultar esse dado antes de guardá-lo ou mostrá-lo."
        acao += (" Se você digitou sua senha em algum lugar, troque-a agora." if pii_type == "SENHA"
                 else " Enquanto isso, evite digitar dados pessoais em campos de texto livre.")
        return {
            "titulo": TITULO[pii_type],
            "risco": f"O sistema deixa {DADO[pii_type]} {destino}. Isso aumenta o risco de {RISCO_TIPO[pii_type]}.",
            "o_que_fazer": acao,
        }
    titulo, risco, acao = REGRA_SIMPLES.get(issue["rule_id"], (
        "Foi encontrada uma falha de segurança", "A falha pode expor dados dos moradores.",
        "A equipe deve corrigir a falha."))
    return {"titulo": titulo, "risco": risco, "o_que_fazer": acao}


def _why_invalid(data, issue=None):
    """Devolve o motivo do descarte, ou None se o texto do LLM pode ser usado."""
    if not isinstance(data, dict):
        return "formato"
    textos = []
    for chave, limite in {"risco": 320, "o_que_fazer": 320}.items():
        valor = data.get(chave)
        if not isinstance(valor, str) or not valor.strip():
            return f"campo ausente: {chave}"
        if len(valor) > limite:
            return f"texto longo: {chave}"
        if any(j in valor.lower() for j in JARGAO_PROIBIDO):
            return "jargão técnico"
        if find_pii(valor):  # a saída do LLM também não pode conter PII
            return "PII na saída"
        textos.append(valor.lower())
    texto = " ".join(textos)
    for termo in INVENTADOS:
        if termo in texto:
            return f"consequência inventada: {termo}"
    if issue is None or issue.get("pii_type") not in DADO:
        return None
    destino = DESTINO_TERMOS[issue.get("sink") or "codigo"]
    if not any(t in texto for t in destino):
        return "não cita o destino real"
    for t in LOCAIS_EXCLUSIVOS:
        if t in texto and t not in destino:
            return f"cita lugar errado: {t}"
    if not any(t in texto for t in DADO_TERMOS[issue["pii_type"]]):
        return "não cita o dado"
    return None


def _valid(data, issue=None) -> bool:
    return _why_invalid(data, issue) is None


def _ask_llm(prompt: str, fmt) -> dict:
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": fmt,
              "options": {"temperature": 0.2}},
        timeout=OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()
    return json.loads(resp.json()["response"])


def build_citizen_alert(issue: dict, use_ai: bool = True) -> dict:
    """Devolve o alerta ao cidadão para um achado. Sempre devolve algo: a IA é um refinamento."""
    pontos = exposure_points(issue)
    alert, fonte = default_alert(issue), "padrao"
    chave = (issue["rule_id"], issue.get("pii_type"), issue.get("sink"))
    descarte = None

    if use_ai and chave in _CACHE:  # mesma categoria: reaproveita o texto, sem nova chamada ao LLM
        alert, fonte = dict(_CACHE[chave]), "ia"
    elif use_ai:
        prompt = build_prompt(issue)
        try:
            try:
                data = _ask_llm(prompt, ALERT_SCHEMA)  # saída restrita por JSON schema
            except requests.HTTPError:
                data = _ask_llm(prompt, "json")        # Ollama antigo, sem suporte a schema
            motivo = _why_invalid(data, issue)
            if motivo is None:
                # O título é fixo por tipo de dado: o modelo de 3B errava gênero ("Seu senha")
                alert = {"titulo": alert["titulo"], "risco": data["risco"].strip(),
                         "o_que_fazer": data["o_que_fazer"].strip()}
                fonte = "ia"
                _CACHE[chave] = dict(alert)
            else:
                descarte = motivo
                logger.warning("Alerta do LLM descartado (%s); usando o alerta-padrão.", motivo)
        except (requests.RequestException, ValueError, KeyError) as exc:
            logger.warning("Ollama indisponível ou resposta inválida (%s); usando o alerta-padrão.", type(exc).__name__)

    alert.update({"nivel": risk_level(pontos), "pontos": pontos, "fonte": fonte})
    if descarte:
        alert["descarte"] = descarte  # só para diagnóstico; não vai para o banco
    return alert


def clear_cache():
    _CACHE.clear()
