"""Pontos de exposição por achado de PII. A Etapa 4 soma estes pontos no Risco Cidadão.

pontos = peso do tipo de PII (1 a 3) x peso do destino (1 a 3), logo de 1 a 9.
Quem decide o número é uma regra determinística: o LLM só escreve o texto do alerta.
"""
from app.engine.pii_taint import SINK_META
from app.pii.detectors import PII_META

# PII fixa no código fica versionada e é lida por todos que acessam o repositório.
PESO_CODIGO = 2


def exposure_points(issue: dict) -> int | None:
    """Devolve os pontos do achado, ou None se ele não for de PII."""
    pii_type = issue.get("pii_type")
    if not pii_type or pii_type not in PII_META:
        return None
    sink = issue.get("sink")
    peso_destino = SINK_META[sink]["weight"] if sink in SINK_META else PESO_CODIGO
    return PII_META[pii_type]["weight"] * peso_destino


def risk_level(points: int | None) -> str:
    if points is None:
        return "medio"
    if points >= 7:
        return "critico"
    if points >= 4:
        return "alto"
    if points >= 2:
        return "medio"
    return "baixo"
