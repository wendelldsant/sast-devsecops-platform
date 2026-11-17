"""Validação do módulo de PII (Etapa 1) com dados FICTÍCIOS.

Rodar da raiz do repositório:  python scripts/validar_pii.py
Mede acerto por tipo (precisão e revocação), mostra o mascaramento e testa a regra
PII_HARDCODED no motor SAST. A saída serve como evidência na auditoria.
"""
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.parser import scan_file  # noqa: E402
from app.pii import find_pii, mask_pii  # noqa: E402

CPF = "529.982.247-25"  # fictício, válido pelo dígito verificador

# (texto, tipos esperados, é limitação conhecida?)
CASOS = [
    (f"Moro na Rua das Flores, 100. Meu CPF é {CPF}", ["CPF"], False),
    ("cpf: 52998224725", ["CPF"], False),
    ("documento 529 982 247 25", ["CPF"], False),
    ("Me liguem: (11) 98765-4321", ["TELEFONE"], False),
    ("whats 11987654321", ["TELEFONE"], False),
    ("contato +55 21 3456-7890", ["TELEFONE"], False),
    ("escreva para maria.teste@exemplo.com", ["EMAIL"], False),
    ("senha do portal: Zel@2026x", ["SENHA"], False),
    ("a senha do wifi é abc12345", ["SENHA"], False),
    ("eu tenho diabetes e preciso de acesso", ["SAUDE"], False),
    ("meu pai faz tratamento de câncer", ["SAUDE"], False),
    ("laudo CID F32.1", ["SAUDE"], False),
    (f"João, CPF {CPF}, tel (11) 91234-5678, joao@exemplo.com, tenho hipertensão",
     ["CPF", "TELEFONE", "EMAIL", "SAUDE"], False),
    # Textos sem PII: o detector NÃO pode disparar
    ("Buraco grande na Av. Paulista, 1000, em frente ao metrô", [], False),
    ("protocolo 20261116123", [], False),
    ("Chamado SP-2026-0012345 aberto", [], False),
    ("CPF com dígito errado 529.982.247-26", [], False),
    ("sequência repetida 111.111.111-11", [], False),
    ("foco de dengue na esquina", [], False),
    ("calçada ruim para cadeirante", [], False),
    ("poste apagado desde 12/11/2026 às 19:30", [], False),
    ("lixo acumulado há 15 dias, CEP 01310-100", [], False),
    ("lâmpada queimada no número 4455 da Rua Augusta", [], False),
    # Limitações conhecidas (declaradas, não escondidas)
    ("minha senha 1234", ["SENHA"], True),
    ("sou cadeirante e preciso de rampa", ["SAUDE"], True),
    ("telefone 3456-7890", ["TELEFONE"], True),
    ("cpf 5 2 9 9 8 2 2 4 7 2 5", ["CPF"], True),
]


def avaliar():
    tp, fp, fn = Counter(), Counter(), Counter()
    falhas = 0
    print(f"{'#':>2} {'resultado':<10} {'esperado':<28} {'encontrado':<28} texto")
    for i, (texto, esperado, limite) in enumerate(CASOS, 1):
        achado = sorted(m.pii_type for m in find_pii(texto))
        esperado = sorted(esperado)
        ok = achado == esperado
        if not limite:
            for t in set(achado) | set(esperado):
                (tp if t in achado and t in esperado else fp if t in achado else fn)[t] += 1
            falhas += not ok
        rotulo = "ok" if ok else ("LIMITE" if limite else "FALHA")
        print(f"{i:>2} {rotulo:<10} {','.join(esperado) or '-':<28} {','.join(achado) or '-':<28} {texto[:60]}")
    return tp, fp, fn, falhas


def mostrar_metricas(tp, fp, fn):
    print("\nMétricas por tipo (casos normais, sem as limitações declaradas)")
    print(f"{'tipo':<10} {'VP':>3} {'FP':>3} {'FN':>3} {'precisão':>9} {'revocação':>10}")
    for t in sorted(set(tp) | set(fp) | set(fn)):
        p = tp[t] / (tp[t] + fp[t]) if tp[t] + fp[t] else 1.0
        r = tp[t] / (tp[t] + fn[t]) if tp[t] + fn[t] else 1.0
        print(f"{t:<10} {tp[t]:>3} {fp[t]:>3} {fn[t]:>3} {p:>9.0%} {r:>10.0%}")


def mostrar_mascaramento():
    print("\nMascaramento (sanitizador mask_pii)")
    entrada = f"Sou João, CPF {CPF}, tel (11) 91234-5678, joao@exemplo.com. Tenho diabetes. senha: abc12345"
    saida = mask_pii(entrada)
    print("  entrada :", entrada)
    print("  saída   :", saida)
    print("  idempotente (reanálise sem achados):", find_pii(saida) == [])


def testar_motor():
    print("\nRegra PII_HARDCODED no motor SAST")
    codigo = (
        '"""Docstring com CPF 529.982.247-25 não deve ser analisada."""\n'
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        f'USUARIO_TESTE = "CPF {CPF}"\n'
        'CONTATO = "tel (11) 91234-5678"\n'
        'AVISO = "paciente tem diabetes"  # saúde não é checada em literal de código\n'
    )
    with tempfile.TemporaryDirectory() as tmp:
        arq = Path(tmp) / "amostra.py"
        arq.write_text(codigo, encoding="utf-8")
        achados = scan_file(str(arq))
    for a in achados:
        print(f"  linha {a['line']} | {a['rule_id']} | {a['severity']} | {a['pii_type']} "
              f"({a['confidence']}) | {a['message']}")
    vazou = CPF in str(achados) or "91234-5678" in str(achados)
    print("  valor da PII aparece no relatório:", "SIM (falha)" if vazou else "não")
    return len(achados) == 2 and not vazou


if __name__ == "__main__":
    tp, fp, fn, falhas = avaliar()
    mostrar_metricas(tp, fp, fn)
    mostrar_mascaramento()
    motor_ok = testar_motor()
    print(f"\nRESULTADO: {'APROVADO' if not falhas and motor_ok else 'REPROVADO'} "
          f"({falhas} falhas nos casos normais; limitações declaradas listadas como LIMITE)")
    sys.exit(0 if not falhas and motor_ok else 1)
