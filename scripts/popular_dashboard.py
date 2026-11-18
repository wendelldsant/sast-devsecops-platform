"""Popula o dashboard com a história do Risco Cidadão: vulnerável -> parcial -> corrigido.

Rodar com a API no ar (docker compose up), da raiz do repositório:
    python scripts/popular_dashboard.py            # alertas-padrão (rápido)
    python scripts/popular_dashboard.py --ia       # alertas escritos pelo Ollama (leva alguns minutos)
    python scripts/popular_dashboard.py --url http://localhost:8000
Envia as 3 versões do protótipo da Zeladoria com o MESMO nome de arquivo (como se fosse o mesmo
arquivo sendo corrigido ao longo do tempo). Depois abra http://localhost:8000/dashboard.
"""
import argparse
import sys
from pathlib import Path

import requests

PASTA = Path(__file__).resolve().parent.parent / "tests" / "prototipo_zeladoria"
ETAPAS = [("vulneravel.py", "1) vulnerável"), ("parcial.py", "2) correção parcial"), ("corrigido.py", "3) corrigido")]
NOME = "zeladoria_api.py"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--ia", action="store_true", help="usa o Ollama para escrever os alertas")
    args = ap.parse_args()

    for arquivo, titulo in ETAPAS:
        try:
            resp = requests.post(
                f"{args.url}/scan",
                params={"use_ai": str(args.ia).lower()},
                files={"file": (NOME, (PASTA / arquivo).read_bytes())},
                timeout=900,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            sys.exit(f"Falha ao chamar a API em {args.url}: {exc}\nA API está no ar? (docker compose up)")
        dados = resp.json()
        risco = dados["citizen_risk"]
        print(f"{titulo:<22} achados={dados['issues_found']:<2} "
              f"Risco Cidadão={risco['score']:>3} ({risco['nivel']}, {risco['pontos']} pts)")
    print(f"\nAbra {args.url}/dashboard")


if __name__ == "__main__":
    main()
