"""Gera os alertas ao cidadão (Etapa 3) para os achados do protótipo vulnerável da Zeladoria.

Rodar da raiz do repositório, com o Ollama ligado:
    python scripts/alertas_prototipo.py                  # usa a IA (Ollama) e cai no alerta-padrão se falhar
    python scripts/alertas_prototipo.py --sem-ia         # só os alertas-padrão
    python scripts/alertas_prototipo.py --saida docs/cyber/evidencias/etapa3-alertas.txt   # também salva em UTF-8
Mostra, para cada achado, o texto técnico do SAST e o alerta traduzido para o morador.
"""
import argparse
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ai.citizen_alert import build_citizen_alert  # noqa: E402
from app.engine.parser import scan_file  # noqa: E402

ALVO = Path(__file__).resolve().parent.parent / "tests" / "prototipo_zeladoria" / "vulneravel.py"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sem-ia", action="store_true")
    ap.add_argument("--saida")
    args = ap.parse_args()

    linhas = []

    def out(texto=""):
        print(texto)
        linhas.append(texto)

    achados = sorted(scan_file(str(ALVO)), key=lambda a: a["line"])
    fontes = Counter()
    out(f"Alertas ao cidadão para {ALVO.name} (IA {'desligada' if args.sem_ia else 'ligada: Ollama'})")
    for a in achados:
        inicio = time.time()
        alerta = build_citizen_alert(a, use_ai=not args.sem_ia)
        fontes[alerta["fonte"]] += 1
        out(f"\n--- L{a['line']} {a['rule_id']} | {a.get('pii_type', '-')} | destino={a.get('sink', 'código')}")
        out(f"TÉCNICO : {a['message'].split(' Fluxo:')[0]}")
        out(f"CIDADÃO : [{alerta['nivel'].upper()} | {alerta['pontos']} pts | fonte={alerta['fonte']} "
            f"| {time.time() - inicio:.1f}s]")
        out(f"  título : {alerta['titulo']}")
        out(f"  risco  : {alerta['risco']}")
        out(f"  ação   : {alerta['o_que_fazer']}")
        if alerta.get("descarte"):
            out(f"  (texto do LLM descartado: {alerta['descarte']})")
    out(f"\nResumo: {len(achados)} alertas | fonte: {dict(fontes)}")

    if args.saida:
        Path(args.saida).write_text("\n".join(linhas) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
