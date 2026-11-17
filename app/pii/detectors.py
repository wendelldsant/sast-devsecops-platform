"""Detecção de dados pessoais (PII) em texto livre, com foco em português do Brasil.

Princípios de projeto (ver docs/cyber/etapa1-pii.md):
- Precisão antes de cobertura: cada detector combina padrão + validação + contexto.
- Cada achado tem confiança "alta" ou "media", para o dashboard separar certeza de suspeita.
- O módulo NUNCA guarda nem devolve o valor encontrado, só a posição (start/end).
  Assim o próprio scanner não vira um vazamento de PII em relatórios ou logs.
"""
import re
from dataclasses import dataclass

# Metadados por tipo. "weight" alimenta o Risco Cidadão (Etapa 4).
# Base legal do peso: CPF/telefone/e-mail são dado pessoal comum (LGPD art. 5, I);
# saúde é dado pessoal sensível (art. 5, II); senha não é dado pessoal, mas é credencial crítica.
PII_META = {
    "CPF": {"category": "comum", "weight": 2, "cwe": "CWE-359", "severity": "high"},
    "TELEFONE": {"category": "comum", "weight": 1, "cwe": "CWE-359", "severity": "medium"},
    "EMAIL": {"category": "comum", "weight": 1, "cwe": "CWE-359", "severity": "medium"},
    "SAUDE": {"category": "sensivel", "weight": 3, "cwe": "CWE-359", "severity": "critical"},
    "SENHA": {"category": "credencial", "weight": 3, "cwe": "CWE-798", "severity": "high"},
    # Tipos inferidos pelo taint a partir do NOME do campo (sem detector de texto):
    # texto livre pode conter qualquer PII; um objeto inteiro carrega vários campos de uma vez.
    "TEXTO_LIVRE": {"category": "livre", "weight": 2, "cwe": "CWE-200", "severity": "high"},
    "MULTIPLOS": {"category": "misto", "weight": 3, "cwe": "CWE-200", "severity": "critical"},
}

CONFIDENCE_RANK = {"alta": 2, "media": 1}
# Desempate quando dois detectores disputam o mesmo trecho com a mesma confiança.
TYPE_PRIORITY = ["SENHA", "SAUDE", "TELEFONE", "CPF", "EMAIL"]


@dataclass(frozen=True)
class PIIMatch:
    pii_type: str
    start: int
    end: int
    confidence: str  # "alta" | "media"

    @property
    def category(self) -> str:
        return PII_META[self.pii_type]["category"]

    @property
    def weight(self) -> int:
        return PII_META[self.pii_type]["weight"]

    @property
    def severity(self) -> str:
        return PII_META[self.pii_type]["severity"]

    @property
    def cwe(self) -> str:
        return PII_META[self.pii_type]["cwe"]


# ---------------------------------------------------------------- CPF
_CPF_RE = re.compile(r"(?<![\d.\-/])\d{3}[.\s]?\d{3}[.\s]?\d{3}[-\s]?\d{2}(?!\d)")
_CPF_CONTEXT_RE = re.compile(r"cpf\W{0,6}$", re.IGNORECASE)


def is_valid_cpf(value: str) -> bool:
    """Valida o CPF pelos dois dígitos verificadores (módulo 11).

    Rejeita sequências de 11 dígitos iguais (000.000.000-00, 111.111.111-11...):
    elas passam na conta, mas não são CPFs reais.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for size in (9, 10):
        pesos = range(size + 1, 1, -1)  # 10..2 no 1º dígito, 11..2 no 2º
        total = sum(int(d) * p for d, p in zip(digits[:size], pesos))
        if (total * 10) % 11 % 10 != int(digits[size]):
            return False
    return True


def _find_cpf(text: str) -> list[PIIMatch]:
    found = []
    for m in _CPF_RE.finditer(text):
        if not is_valid_cpf(m.group()):
            continue
        has_separator = bool(re.search(r"[.\-]", m.group()))
        has_context = bool(_CPF_CONTEXT_RE.search(text[max(0, m.start() - 12):m.start()]))
        confidence = "alta" if (has_separator or has_context) else "media"
        found.append(PIIMatch("CPF", m.start(), m.end(), confidence))
    return found


# ---------------------------------------------------------------- Telefone
_VALID_DDDS = set(
    "11 12 13 14 15 16 17 18 19 21 22 24 27 28 31 32 33 34 35 37 38 "
    "41 42 43 44 45 46 47 48 49 51 53 54 55 61 62 63 64 65 66 67 68 69 "
    "71 73 74 75 77 79 81 82 83 84 85 86 87 88 89 91 92 93 94 95 96 97 98 99".split()
)
# DDD + (celular: 9 + 8 dígitos | fixo: 2-5 + 7 dígitos). O DDD é obrigatório.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?55[\s.-]?)?\(?(?P<ddd>\d{2})\)?[\s.-]?(?P<num>9\d{4}|[2-5]\d{3})[\s.-]?\d{4}(?!\d)"
)
_PHONE_CONTEXT_RE = re.compile(r"(?:tel\w*|fone|cel\w*|whats\w*|zap|contato|ligar?)\W{0,8}$", re.IGNORECASE)


def _find_phone(text: str) -> list[PIIMatch]:
    found = []
    for m in _PHONE_RE.finditer(text):
        if m.group("ddd") not in _VALID_DDDS:
            continue
        formatted = bool(re.search(r"[()+\-.\s]", m.group()))
        if formatted:
            found.append(PIIMatch("TELEFONE", m.start(), m.end(), "alta"))
        elif _PHONE_CONTEXT_RE.search(text[max(0, m.start() - 25):m.start()]):
            found.append(PIIMatch("TELEFONE", m.start(), m.end(), "media"))
        # Só dígitos e sem palavra de contexto (ex.: número de protocolo): ignorado de propósito.
    return found


# ---------------------------------------------------------------- E-mail
_EMAIL_RE = re.compile(r"(?<![\w.%+-])[\w.%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def _find_email(text: str) -> list[PIIMatch]:
    return [PIIMatch("EMAIL", m.start(), m.end(), "alta") for m in _EMAIL_RE.finditer(text)]


# ---------------------------------------------------------------- Senha / credencial
# Mascara só o VALOR (grupo "valor"), mantendo "senha:" legível no log.
_SENHA_RE = re.compile(
    r"\b(?:senha|password|passwd|pwd|token|api[_-]?key|chave)\b"
    r"(?:\s+\w+){0,2}?\s*(?:[:=]|\bé\b|\beh\b)\s*(?P<valor>[^\s,;]+)",
    re.IGNORECASE,
)
_MASK_TAG_RE = re.compile(r"^\[[A-Z_]+\]$")
_NOT_A_SECRET = {"none", "null", "true", "false", "nan"}


def _find_senha(text: str) -> list[PIIMatch]:
    found = []
    for m in _SENHA_RE.finditer(text):
        valor = m.group("valor")
        if len(valor) < 3 or valor.lower() in _NOT_A_SECRET or _MASK_TAG_RE.match(valor):
            continue  # evita "token = None" e reanálise de texto já mascarado
        found.append(PIIMatch("SENHA", m.start("valor"), m.end("valor"), "alta"))
    return found


# ---------------------------------------------------------------- Saúde (dado sensível)
# Heurística por léxico + marcador de contexto pessoal ("tenho", "sofro de", "diagnóstico de"...).
# Fica de fora de propósito: "dengue" (queixa de saúde pública sobre foco no bairro, não dado de
# uma pessoa) e "cadeirante"/"deficiência" (aparecem em relatos de acessibilidade da calçada).
_SAUDE_TERMOS = (
    r"diabetes|diab[eé]tic[oa]|hipertens[aã]o|hipertens[oa]|hiv|aids|soropositiv[oa]|c[aâ]ncer|"
    r"depress[aã]o|ansiedade|epilepsia|asma|tuberculose|hansen[ií]ase|esquizofrenia|bipolar|"
    r"tdah|autismo|alzheimer|parkinson|covid|cardiopatia|insufici[eê]ncia\s+renal|"
    r"hemodi[aá]lise|quimioterapia|insulina"
)
_SAUDE_MARCADORES = (
    r"tenho|tem|sofro|sofre|sou|[eé]|est[aá]|portador(?:a)?|diagn[oó]stico|diagnosticad[oa]|"
    r"tratamento|uso|tomo|toma|faz"
)
_SAUDE_RE = re.compile(
    rf"\b(?:{_SAUDE_MARCADORES})\b(?:\s+\w+){{0,3}}?\s+(?P<termo>{_SAUDE_TERMOS})\b",
    re.IGNORECASE,
)
_CID_RE = re.compile(r"\bCID[\s:-]*[A-Z]\d{2}(?:\.\d)?\b", re.IGNORECASE)


def _find_saude(text: str) -> list[PIIMatch]:
    found = [PIIMatch("SAUDE", m.start("termo"), m.end("termo"), "media") for m in _SAUDE_RE.finditer(text)]
    found += [PIIMatch("SAUDE", m.start(), m.end(), "alta") for m in _CID_RE.finditer(text)]
    return found


_DETECTORS = {
    "CPF": _find_cpf,
    "TELEFONE": _find_phone,
    "EMAIL": _find_email,
    "SENHA": _find_senha,
    "SAUDE": _find_saude,
}


# ---------------------------------------------------------------- API pública
def find_pii(text: str, types: set[str] | None = None) -> list[PIIMatch]:
    """Encontra PII em `text`. `types` restringe os tipos (padrão: todos).

    Quando dois achados se sobrepõem, vale o de maior confiança; no empate, a ordem de TYPE_PRIORITY.
    """
    candidates = []
    for pii_type, detector in _DETECTORS.items():
        if types is None or pii_type in types:
            candidates += detector(text)

    candidates.sort(key=lambda c: (-CONFIDENCE_RANK[c.confidence], TYPE_PRIORITY.index(c.pii_type), c.start))
    accepted = []
    for cand in candidates:
        if all(cand.end <= a.start or cand.start >= a.end for a in accepted):
            accepted.append(cand)
    return sorted(accepted, key=lambda c: c.start)


def mask_pii(text: str, matches: list[PIIMatch] | None = None) -> str:
    """Troca cada PII por uma etiqueta ([CPF], [TELEFONE]...). Sanitizador padrão do projeto."""
    if matches is None:
        matches = find_pii(text)
    for m in sorted(matches, key=lambda x: x.start, reverse=True):
        text = text[:m.start] + f"[{m.pii_type}]" + text[m.end:]
    return text
