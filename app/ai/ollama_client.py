import json
import os
import html
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "180"))
VALID_SEVERITIES = {"critical", "high", "medium", "low"}

RULE_HINTS = {
    "HARDCODED_SECRET": (
        'Leia o segredo de uma variável de ambiente com os.environ["NOME"] '
        "(sem valor padrão) ou de um gerenciador de segredos. "
        "Nunca gere um valor aleatório no lugar do segredo."
    ),
    "DANGEROUS_FUNCTION": (
        "Substitua eval/exec por ast.literal_eval quando o objetivo for interpretar "
        "um literal, tratando ValueError e SyntaxError."
    ),
    "SHELL_INJECTION": (
        "Passe os argumentos como lista (use shlex.split se vier uma string) "
        "e use shell=False."
    ),
    "TAINTED_DATA_FLOW": (
        "Valide a entrada contra uma lista de valores permitidos antes de usá-la "
        "e evite eval/exec/os.system com dados do usuário."
    ),
}

PROMPT_TEMPLATE = """Você é um especialista em segurança de aplicações (AppSec).
Um analisador estático (SAST) encontrou um possível problema em um código Python.

Regra: {rule_id} ({cwe})
Descrição: {message}
Linha: {line}

Trecho de código (a linha suspeita está marcada com >>>):
{snippet}

Orientação de correção para esta regra: {hint}

Responda SOMENTE com um JSON válido, com exatamente estas chaves:
- "severity": um destes valores: "critical", "high", "medium", "low"
- "false_positive": true ou false
- "explanation": explicação curta do risco (máximo 2 frases, em português)
- "remediation": trecho de código Python corrigido, como texto

Regras para a correção:
- Nunca use valores padrão para segredos (senhas, tokens, chaves).
- Inclua os imports necessários no trecho corrigido.
- Use apenas bibliotecas da biblioteca padrão do Python ou bibliotecas amplamente conhecidas.
- Não escape caracteres em HTML.
"""

def build_snippet(source_code: str, line: int, context: int = 3) -> str:
    """Extrai algumas linhas ao redor da linha suspeita, marcando-a com >>>."""
    lines = source_code.splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    out = []
    for i in range(start, end):
        marker = ">>>" if i == line - 1 else "   "
        out.append(f"{marker} {i + 1}: {lines[i]}")
    return "\n".join(out)


def analyze_issue(snippet: str, issue: dict) -> dict | None:
    """Pede ao LLM local a classificação e a correção. Retorna None se a IA falhar."""

    prompt = PROMPT_TEMPLATE.format(
        rule_id=issue["rule_id"],
        cwe=issue["cwe"],
        message=issue["message"],
        line=issue["line"],
        snippet=snippet,
        hint=RULE_HINTS.get(issue["rule_id"], "Aplique a correção mais segura e simples."),
    )

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1},
            },
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        data = json.loads(response.json()["response"])
    except (requests.RequestException, json.JSONDecodeError, KeyError):
        return None

    if not isinstance(data, dict):
        return None

    severity = str(data.get("severity", "")).lower()
    if severity not in VALID_SEVERITIES:
        severity = issue["severity"]  # resposta inválida: mantém a severidade da regra

    return {
        "ai_severity": severity,
        "ai_false_positive": bool(data.get("false_positive", False)),
        "ai_explanation": html.unescape(str(data.get("explanation", "")))[:1000],
        "ai_remediation": html.unescape(str(data.get("remediation", "")))[:4000],
    }