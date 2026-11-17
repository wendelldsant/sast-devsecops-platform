"""Auditoria SAST do protótipo da Zeladoria (Etapa 2: taint analysis de PII).

Rodar da raiz do repositório:  python scripts/auditar_prototipo.py
Escaneia a versão vulnerável e a corrigida e mostra o fluxo de cada vazamento
(fonte -> variáveis -> destino). A saída é a evidência da "Auditoria do Protótipo".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.parser import scan_file  # noqa: E402

PASTA = Path(__file__).resolve().parent.parent / "tests" / "prototipo_zeladoria"
ALVOS = [("vulneravel.py", "ANTES (vulnerável)"), ("corrigido.py", "DEPOIS (corrigido)")]
REGRAS_PII = {"PII_LEAK", "PII_HARDCODED"}


def auditar(arquivo, titulo):
    achados = [a for a in scan_file(str(PASTA / arquivo)) if a["rule_id"] in REGRAS_PII]
    achados.sort(key=lambda a: a["line"])
    print(f"\n=== {titulo}: tests/prototipo_zeladoria/{arquivo} ===")
    if not achados:
        print("  nenhum vazamento de PII encontrado")
    for a in achados:
        destino = a.get("sink", "código")
        print(f"  L{a['line']:<3} {a['rule_id']:<13} {a['severity']:<8} {a['pii_type']:<12} "
              f"destino={destino:<12} confiança={a['confidence']}")
        if a["rule_id"] == "PII_LEAK":
            fluxo = a["message"].split("Fluxo: ")[1].split(". Aplique")[0]
            print(f"        fluxo: {fluxo}")
    bloqueantes = sum(a["severity"] == "critical" for a in achados)
    print(f"  total: {len(achados)} | bloqueantes (critical): {bloqueantes} | "
          f"Security Gate: {'REPROVADO' if bloqueantes else 'APROVADO'}")
    return achados


if __name__ == "__main__":
    antes = auditar(*ALVOS[0])
    depois = auditar(*ALVOS[1])
    vazamentos = [a for a in antes if a["rule_id"] == "PII_LEAK"]
    destinos = sorted({a["sink"] for a in vazamentos})
    print(f"\nResumo: {len(vazamentos)} vazamentos em {len(destinos)} destinos ({', '.join(destinos)}) "
          f"antes; {len(depois)} depois.")
    ok = len(vazamentos) == 5 and not depois
    print("RESULTADO:", "APROVADO" if ok else "REPROVADO")
    sys.exit(0 if ok else 1)
