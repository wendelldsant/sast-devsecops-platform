"""Testes da Etapa 4: Risco Cidadão (cálculo, histórico por scan e endpoint do dashboard). Dados FICTÍCIOS.

Rodar da raiz do repositório:  python -m pytest tests/test_dashboard_risk.py -v
"""
import os
import tempfile
from pathlib import Path

import pytest
import requests

# Banco SQLite temporário, nunca o real. Precisa vir antes de importar app.api.
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/dash.db"

from app import risk  # noqa: E402

PROTO = Path(__file__).parent / "prototipo_zeladoria"
HTML = Path(__file__).parent.parent / "app" / "api" / "static" / "dashboard.html"


# ---------------------------------------------------------------- cálculo
def test_pontos_ponderados_pela_confianca():
    assert risk.weighted_points(6, "alta") == 6
    assert risk.weighted_points(6, "media") == 3
    assert risk.weighted_points(None, "alta") == 0


def test_score_com_teto_em_100():
    assert risk.citizen_risk_score(0) == 0
    assert risk.citizen_risk_score(15) == 50
    assert risk.citizen_risk_score(26) == 87
    assert risk.citizen_risk_score(300) == 100


def test_niveis_do_risco_cidadao():
    assert [risk.citizen_risk_level(s) for s in (0, 1, 24, 25, 49, 50, 74, 75, 100)] == [
        "nenhum", "baixo", "baixo", "medio", "medio", "alto", "alto", "critico", "critico"]


# ---------------------------------------------------------------- API
@pytest.fixture()
def api(monkeypatch):
    from fastapi.testclient import TestClient
    from app.api import main
    from app.api.models import ScanResult, ScanRun
    monkeypatch.setattr(requests, "post", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError()))
    with main.engine.begin() as conn:  # banco limpo a cada teste
        conn.execute(ScanResult.__table__.delete())
        conn.execute(ScanRun.__table__.delete())
    return TestClient(main.app)


def enviar(api, versao, nome="zeladoria_api.py"):
    r = api.post("/scan?use_ai=false", files={"file": (nome, (PROTO / f"{versao}.py").read_bytes())})
    assert r.status_code == 200
    return r.json()


def risco(api):
    return api.get("/api/dashboard/citizen-risk").json()


def test_banco_vazio_nao_quebra(api):
    d = risco(api)
    assert d["risk"]["score"] == 0 and d["risk"]["level"] == "nenhum" and d["risk"]["files"] == 0
    assert d["by_type"] == d["by_sink"] == d["timeline"] == d["top_findings"] == []


def test_scan_devolve_o_risco_da_execucao(api):
    assert enviar(api, "vulneravel")["citizen_risk"] == {"score": 87, "nivel": "critico", "pontos": 26.0}
    assert enviar(api, "parcial")["citizen_risk"] == {"score": 50, "nivel": "alto", "pontos": 15.0}
    assert enviar(api, "corrigido")["citizen_risk"] == {"score": 0, "nivel": "nenhum", "pontos": 0.0}


def test_arquivo_sem_achados_tambem_gera_execucao(api):
    enviar(api, "vulneravel")
    enviar(api, "corrigido")  # 0 achados: sem scan_runs o risco continuaria em 87
    d = risco(api)
    assert d["risk"]["score"] == 0 and d["risk"]["files"] == 1 and d["top_findings"] == []


def test_estado_atual_usa_so_o_ultimo_scan_de_cada_arquivo(api):
    enviar(api, "vulneravel")
    enviar(api, "parcial")
    d = risco(api)
    assert d["risk"]["score"] == 50 and d["risk"]["findings"] == 2  # os 6 achados antigos não contam


def test_linha_do_tempo_mostra_a_queda_do_risco(api):
    for versao in ("vulneravel", "parcial", "corrigido"):
        enviar(api, versao)
    d = risco(api)
    assert [p["risk_score"] for p in d["timeline"]] == [87, 50, 0]
    assert [p["pii_findings"] for p in d["timeline"]] == [6, 2, 0]


def test_agregados_por_tipo_e_destino(api):
    enviar(api, "vulneravel")
    d = risco(api)
    tipos = {t["pii_type"]: (t["count"], t["points"]) for t in d["by_type"]}
    assert tipos == {"SENHA": (1, 9.0), "CPF": (3, 14.0), "TEXTO_LIVRE": (1, 2.0), "TELEFONE": (1, 1.0)}
    destinos = {s["sink"]: s["points"] for s in d["by_sink"]}
    assert destinos == {"excecao": 9.0, "resposta_api": 6.0, "arquivo": 4.0, "codigo": 4.0, "log": 2.0, "print": 1.0}
    assert d["by_type"][0]["pii_type"] == "CPF"  # ordenado por pontos


def test_maiores_riscos_ordenados_e_sem_valores_de_pii(api):
    texto = None
    r = api.post("/scan?use_ai=false", files={"file": ("zeladoria_api.py", (PROTO / "vulneravel.py").read_bytes())})
    texto = r.text
    resp = api.get("/api/dashboard/citizen-risk")
    top = resp.json()["top_findings"]
    assert [t["points"] for t in top] == sorted((t["points"] for t in top), reverse=True)
    assert top[0]["pii_type"] == "SENHA" and top[0]["level"] == "critico" and top[0]["alert_source"] == "padrao"
    assert top[0]["alert_title"] and top[0]["alert_risk"] and top[0]["alert_action"]
    assert "529.982.247-25" not in resp.text and "529.982.247-25" not in texto


def test_dois_arquivos_somam_os_pontos(api):
    enviar(api, "vulneravel", nome="a.py")
    enviar(api, "parcial", nome="b.py")
    d = risco(api)
    assert d["risk"]["files"] == 2 and d["risk"]["points"] == 41.0 and d["risk"]["score"] == 100  # teto


def test_linhas_antigas_sem_scan_id_sao_ignoradas(api):
    from app.api import main
    from app.api.models import ScanResult
    with main.engine.begin() as conn:
        conn.execute(ScanResult.__table__.insert().values(
            filename="antigo.py", line=1, rule_id="PII_LEAK", pii_type="CPF", sink="log", alert_points=2))
    assert risco(api)["risk"]["score"] == 0


# ---------------------------------------------------------------- página
def test_pagina_tem_a_secao_e_nao_usa_innerhtml_para_dados():
    html = HTML.read_text(encoding="utf-8")
    assert "Risco Cidadão" in html and "/api/dashboard/citizen-risk" in html
    assert html.count("innerHTML") == 1  # só no comentário que explica a regra de XSS
    assert "textContent" in html
