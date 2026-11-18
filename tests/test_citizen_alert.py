"""Testes da Etapa 3: alerta ao cidadão, pontos de exposição e integração com a API. Dados FICTÍCIOS.

Rodar da raiz do repositório:  python -m pytest tests/test_citizen_alert.py -v
"""
import json
import os
import tempfile
from pathlib import Path

import pytest
import requests
from sqlalchemy import create_engine, inspect, text

# Os testes de API usam SQLite temporário, nunca o banco real. Precisa vir antes de importar app.api.
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/api.db"

from app.ai import citizen_alert as ca  # noqa: E402
from app.pii.detectors import PII_META  # noqa: E402
from app.risk import exposure_points, risk_level  # noqa: E402

PROTOTIPO = Path(__file__).parent / "prototipo_zeladoria" / "vulneravel.py"
BOM = {"titulo": "Seu CPF pode ficar exposto",
       "risco": "Seu CPF apareceu em um arquivo sem proteção. Golpistas poderiam usá-lo em seu nome.",
       "o_que_fazer": "A equipe vai ocultar o CPF antes de guardar."}


class Resp:
    def __init__(self, payload=None, status=200):
        self.payload, self.status = payload, status

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.HTTPError(f"{self.status}")

    def json(self):
        return {"response": json.dumps(self.payload) if not isinstance(self.payload, str) else self.payload}


def leak(pii_type="CPF", sink="arquivo"):
    return {"rule_id": "PII_LEAK", "pii_type": pii_type, "sink": sink, "line": 1, "severity": "critical", "cwe": "CWE-532"}


@pytest.fixture(autouse=True)
def _sem_cache():
    ca.clear_cache()
    yield


# ---------------------------------------------------------------- pontos e nível
def test_pontos_sao_peso_do_tipo_vezes_peso_do_destino():
    assert exposure_points(leak("SENHA", "excecao")) == 9
    assert exposure_points(leak("CPF", "resposta_api")) == 6
    assert exposure_points(leak("TELEFONE", "print")) == 1
    assert exposure_points({"rule_id": "PII_HARDCODED", "pii_type": "CPF"}) == 4  # destino "código" = 2
    assert exposure_points({"rule_id": "HARDCODED_SECRET"}) is None


def test_niveis():
    assert [risk_level(p) for p in (1, 2, 4, 7, 9)] == ["baixo", "medio", "alto", "critico", "critico"]


# ---------------------------------------------------------------- alerta-padrão
@pytest.mark.parametrize("pii_type", sorted(set(PII_META)))
@pytest.mark.parametrize("sink", ["log", "print", "arquivo", "excecao", "resposta_api", None])
def test_alerta_padrao_valido_para_todo_tipo_e_destino(pii_type, sink):
    issue = leak(pii_type, sink)
    assert ca._valid(ca.default_alert(issue), issue)  # formato, tamanho, jargão, PII e consistência


def test_alerta_padrao_para_regras_nao_pii():
    alert = ca.default_alert({"rule_id": "DANGEROUS_FUNCTION"})
    assert ca._valid(alert)
    assert ca.build_citizen_alert({"rule_id": "DANGEROUS_FUNCTION"}, use_ai=False)["nivel"] == "medio"


def test_sem_ia_usa_padrao_e_nao_chama_o_ollama(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: pytest.fail("não deveria chamar o Ollama"))
    out = ca.build_citizen_alert(leak(sink="log"), use_ai=False)
    assert out["fonte"] == "padrao" and out["nivel"] == "medio" and out["pontos"] == 2


# ---------------------------------------------------------------- LLM
def test_prompt_so_tem_categorias_nunca_valores():
    prompt = ca.build_prompt(leak("CPF", "resposta_api"))
    assert "o seu CPF" in prompt and "na resposta enviada ao aplicativo" in prompt
    assert "ocorrencia" not in prompt and "L28" not in prompt  # nenhum nome de variável ou linha


def test_ia_valida_e_aceita(monkeypatch):
    chamadas = []
    monkeypatch.setattr(requests, "post", lambda url, json=None, **k: chamadas.append(json) or Resp(BOM))
    out = ca.build_citizen_alert(leak("CPF", "arquivo"), use_ai=True)
    assert out["fonte"] == "ia" and out["titulo"] == BOM["titulo"]
    assert chamadas[0]["format"] == ca.ALERT_SCHEMA  # saída restrita por JSON schema
    assert out["nivel"] == "alto" and out["pontos"] == 4


def test_ia_com_pii_na_saida_e_descartada(monkeypatch):
    ruim = dict(BOM, risco="O CPF 529.982.247-25 foi exposto.")
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(ruim))
    assert ca.build_citizen_alert(leak(), use_ai=True)["fonte"] == "padrao"


def test_ia_com_destino_errado_e_descartada(monkeypatch):
    # Caso real do Ollama: vazamento na resposta da API descrito como "arquivo"
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(BOM))  # BOM fala de arquivo
    out = ca.build_citizen_alert(leak("CPF", "resposta_api"), use_ai=True)
    assert out["fonte"] == "padrao" and "resposta" in out["risco"]


def test_titulo_e_sempre_o_fixo_por_tipo(monkeypatch):
    # O modelo de 3B errou o gênero ("Seu senha"): o título do LLM é ignorado
    resp = {"titulo": "Seu senha foi exposta", "risco": "Sua senha foi enviada na mensagem de erro exibida na tela.",
            "o_que_fazer": "A equipe vai ocultar a senha das mensagens."}
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(resp))
    out = ca.build_citizen_alert(leak("SENHA", "excecao"), use_ai=True)
    assert out["fonte"] == "ia" and out["titulo"] == "Sua senha pode ficar exposta"


def test_consequencia_inventada_e_descartada_e_o_motivo_e_informado(monkeypatch):
    resp = {"risco": "Sua senha foi enviada na mensagem de erro exibida na tela.",
            "o_que_fazer": "Mantenha-se atento a transações suspeitas."}
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(resp))
    out = ca.build_citizen_alert(leak("SENHA", "excecao"), use_ai=True)
    assert out["fonte"] == "padrao" and out["descarte"].startswith("consequência inventada")


def test_ia_que_nao_cita_o_destino_ou_o_dado_e_descartada(monkeypatch):
    vago = {"risco": "Seus dados podem ser vistos por outras pessoas.",
            "o_que_fazer": "Não compartilhe informações pessoais."}
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(vago))
    assert ca.build_citizen_alert(leak("CPF", "arquivo"), use_ai=True)["fonte"] == "padrao"


def test_cache_por_categoria_evita_nova_chamada_ao_llm(monkeypatch):
    chamadas = []
    monkeypatch.setattr(requests, "post", lambda *a, **k: chamadas.append(1) or Resp(BOM))
    for _ in range(3):
        out = ca.build_citizen_alert(leak("CPF", "arquivo"), use_ai=True)
    assert out["fonte"] == "ia" and len(chamadas) == 1


def test_alerta_padrao_nao_entra_no_cache(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError()))
    assert ca.build_citizen_alert(leak(), use_ai=True)["fonte"] == "padrao"
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(BOM))  # Ollama voltou
    assert ca.build_citizen_alert(leak(), use_ai=True)["fonte"] == "ia"


def test_ia_com_jargao_ou_campo_ausente_e_descartada(monkeypatch):
    for ruim in (dict(BOM, risco="Falha CWE-532 detectada em arquivo com CPF"), {"titulo": "x"}, "não é json", ["lista"]):
        monkeypatch.setattr(requests, "post", lambda *a, _r=ruim, **k: Resp(_r))
        assert ca.build_citizen_alert(leak(), use_ai=True)["fonte"] == "padrao"


def test_ollama_fora_do_ar_usa_padrao(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("recusada")
    monkeypatch.setattr(requests, "post", boom)
    assert ca.build_citizen_alert(leak(), use_ai=True)["fonte"] == "padrao"


def test_ollama_antigo_sem_schema_tenta_de_novo_com_json(monkeypatch):
    formatos = []

    def fake(url, json=None, **k):
        formatos.append(json["format"])
        return Resp(status=400) if isinstance(json["format"], dict) else Resp(BOM)
    monkeypatch.setattr(requests, "post", fake)
    out = ca.build_citizen_alert(leak(), use_ai=True)
    assert out["fonte"] == "ia" and formatos == [ca.ALERT_SCHEMA, "json"]


# ---------------------------------------------------------------- migração
def test_ensure_columns_e_idempotente():
    from app.api.database import NEW_COLUMNS, ensure_columns
    eng = create_engine(f"sqlite:///{tempfile.mkdtemp()}/velho.db")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE scan_results (id INTEGER PRIMARY KEY, filename VARCHAR)"))
    assert set(ensure_columns(eng)) == set(NEW_COLUMNS)
    assert ensure_columns(eng) == []
    assert set(NEW_COLUMNS) <= {c["name"] for c in inspect(eng).get_columns("scan_results")}


# ---------------------------------------------------------------- API
@pytest.fixture()
def client(monkeypatch):
    from fastapi.testclient import TestClient
    from app.api import main
    return TestClient(main.app), main


def test_scan_devolve_alerta_e_grava_no_banco(client, monkeypatch):
    http, main = client
    monkeypatch.setattr(requests, "post", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError()))
    r = http.post("/scan?use_ai=true", files={"file": ("vulneravel.py", PROTOTIPO.read_bytes())})
    assert r.status_code == 200
    issues = r.json()["issues"]
    pii = [i for i in issues if i["rule_id"] in main.PII_RULES]
    assert len(pii) == 6 and all(i["citizen_alert"]["fonte"] == "padrao" for i in pii)
    assert max(i["citizen_alert"]["pontos"] for i in pii) == 9  # senha na exceção
    with main.engine.connect() as c:
        rows = c.execute(text("SELECT rule_id, sink, alert_level, alert_source FROM scan_results")).fetchall()
    assert len(rows) == 6 and {r[1] for r in rows if r[0] == "PII_LEAK"} == {"log", "print", "arquivo", "resposta_api", "excecao"}
    assert "529.982.247-25" not in r.text  # nenhum valor de PII na resposta


def test_achado_de_pii_nunca_manda_trecho_de_codigo_ao_llm(client, monkeypatch):
    http, main = client
    monkeypatch.setattr(main, "analyze_issue", lambda *a, **k: pytest.fail("trecho com PII enviado ao LLM"))
    monkeypatch.setattr(requests, "post", lambda *a, **k: Resp(BOM))
    r = http.post("/scan?use_ai=true", files={"file": ("vulneravel.py", PROTOTIPO.read_bytes())})
    assert r.status_code == 200
    assert all(i["citizen_alert"]["fonte"] in ("ia", "padrao") for i in r.json()["issues"])
