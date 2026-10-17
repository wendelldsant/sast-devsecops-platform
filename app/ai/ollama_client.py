import json
import os

import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "180"))
VALID_SEVERITIES = {"critical", "high", "medium", "low"}

PROMPT_TEMPLATE = """Você é um especialista em segurança de aplicações (AppSec).
Um analisador estático (SAST) encontrou um possível problema em um código Python.

Regra: {rule_id} ({cwe})
Descrição: {message}
Linha: {line}

Trecho de código (a linha suspeita está marcada com >>>):
{snippet}

Responda SOMENTE com um JSON válido, com exatamente estas chaves:
- "severity": um destes valores: "critical", "high", "medium", "low"
- "false_positive": true ou false
- "explanation": explicação curta do risco (máximo 2 frases, em português)
- "remediation": trecho de código Python corrigido, como texto
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
        "ai_explanation": str(data.get("explanation", ""))[:1000],
        "ai_remediation": str(data.get("remediation", ""))[:4000],
    }