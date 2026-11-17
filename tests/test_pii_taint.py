"""Testes do taint analysis de PII (Etapa 2). Dados e protótipos FICTÍCIOS.

Rodar da raiz do repositório:  python -m pytest tests/test_pii_taint.py -v
"""
import ast
import textwrap
from pathlib import Path

from app.engine.parser import scan_file
from app.engine.pii_taint import PIITaintVisitor

PROTOTIPOS = Path(__file__).parent / "prototipo_zeladoria"


def leaks(source):
    tree = ast.parse(textwrap.dedent(source))
    v = PIITaintVisitor()
    v.visit(tree)
    return [(i.sink, i.pii_type, i.confidence) for i in v.issues], v.issues


def sinks(source):
    return [s for s, _, _ in leaks(source)[0]]


# ---------------------------------------------------------------- fontes
def test_fonte_atributo():
    assert sinks("def f(o):\n    print(o.cpf)") == ["print"]


def test_fonte_chave_e_get():
    assert sinks('def f(d):\n    print(d["telefone"])') == ["print"]
    assert sinks('def f(d):\n    print(d.get("email"))') == ["print"]


def test_fonte_parametro_com_nome_de_pii():
    assert sinks("def f(cpf):\n    print(cpf)") == ["print"]


def test_campo_que_nao_e_pii_nao_dispara():
    assert sinks("def f(ocorrencia):\n    print(ocorrencia.tipo, ocorrencia.id)") == []
    assert sinks('def f(d):\n    print(d["tipo"], d.get("bairro"))') == []


def test_objeto_inteiro_vaza_todos_os_campos():
    assert leaks("def f(ocorrencia):\n    print(ocorrencia)")[0] == [("print", "MULTIPLOS", "alta")]


# ---------------------------------------------------------------- propagação
def test_propaga_por_variavel_fstring_concat_format_e_percent():
    src = """
    def f(o):
        a = o.cpf
        b = f"x {a}"
        c = "y" + b
        d = "z {}".format(c)
        e = "w %s" % d
        print(e)
    """
    t, issues = leaks(src)
    assert t == [("print", "CPF", "alta")]
    assert issues[0].message.count("→") == 6  # cpf -> a -> b -> c -> d -> e -> print


def test_propaga_por_dict_lista_e_desempacotamento():
    assert sinks("def f(o):\n    d = {'x': o.cpf}\n    print(d)") == ["print"]
    assert sinks("def f(o):\n    l = [o.telefone]\n    print(l)") == ["print"]
    assert sinks("def f(o):\n    a, b = o.cpf, 1\n    print(a)") == ["print"]


def test_funcao_desconhecida_repassa_com_confianca_media():
    assert leaks("def f(o):\n    x = tratar(o.cpf)\n    print(x)")[0] == [("print", "CPF", "media")]


def test_conversao_de_texto_mantem_confianca_alta():
    assert leaks("def f(o):\n    print(str(o.cpf).strip())")[0] == [("print", "CPF", "alta")]


def test_taint_segue_em_loop_e_comprehension():
    assert sinks("def f(lista):\n    for o in lista:\n        print(o.cpf)") == ["print"]
    assert sinks("def f(lista):\n    print([o.cpf for o in lista])") == ["print"]


# ---------------------------------------------------------------- sanitização e fluxo
def test_mask_pii_remove_o_taint():
    assert sinks("def f(o):\n    print(mask_pii(o.cpf))") == []
    assert sinks("def f(o):\n    x = mask_pii(f'{o.cpf}')\n    print(x)") == []


def test_len_nao_carrega_conteudo():
    assert sinks("def f(o):\n    print(len(o.descricao))") == []


def test_reatribuicao_limpa_remove_o_taint():
    assert sinks("def f(o):\n    x = o.cpf\n    x = 'ok'\n    print(x)") == []


def test_if_else_une_os_ramos():
    src = """
    def f(o, c):
        if c:
            x = o.cpf
        else:
            x = 'ok'
        print(x)
    """
    assert sinks(src) == ["print"]


# ---------------------------------------------------------------- sinks
def test_sink_log():
    assert sinks("def f(o):\n    logger.info(o.cpf)") == ["log"]
    assert sinks("def f(o):\n    logging.warning('%s', o.cpf)") == ["log"]
    assert sinks("def f(o):\n    self.logger.error(o.cpf)") == ["log"]


def test_sink_arquivo():
    assert sinks("def f(o, arq):\n    arq.write(o.cpf)") == ["arquivo"]
    assert sinks("def f(o, arq):\n    json.dump({'c': o.cpf}, arq)") == ["arquivo"]


def test_sink_excecao():
    assert sinks("def f(senha):\n    raise ValueError(f'erro {senha}')") == ["excecao"]
    assert sinks("def f(o):\n    raise HTTPException(400, detail=o.cpf)") == ["excecao"]  # sem duplicar


def test_return_so_e_sink_em_rota():
    rota = "@app.get('/x')\ndef f(o):\n    return {'cpf': o.cpf}"
    assert sinks(rota) == ["resposta_api"]
    assert sinks("def f(o):\n    return {'cpf': o.cpf}") == []


def test_funcao_async_tambem_e_analisada():
    assert sinks("@app.post('/x')\nasync def f(o):\n    return o.cpf") == ["resposta_api"]


def test_metodo_de_classe_e_analisado():
    assert sinks("class S:\n    def f(self, o):\n        print(o.cpf)") == ["print"]


# ---------------------------------------------------------------- relatório
def test_relatorio_nao_contem_valores_so_nomes_de_campo():
    _, issues = leaks("def f(o):\n    x = o.cpf\n    print(x)")
    d = issues[0].to_dict()
    assert d["rule_id"] == "PII_LEAK" and d["severity"] == "critical" and d["sink"] == "print"
    assert "o.cpf" in d["message"] and "mask_pii" in d["message"]


# ---------------------------------------------------------------- protótipo da Zeladoria
def test_prototipo_vulneravel_tem_5_vazamentos_e_1_pii_fixa():
    achados = scan_file(str(PROTOTIPOS / "vulneravel.py"))
    leaks_ = [a for a in achados if a["rule_id"] == "PII_LEAK"]
    assert sorted(a["sink"] for a in leaks_) == ["arquivo", "excecao", "log", "print", "resposta_api"]
    assert [a["rule_id"] for a in achados].count("PII_HARDCODED") == 1
    assert "529.982.247-25" not in str(achados)  # o relatório não vaza o valor


def test_prototipo_corrigido_nao_tem_achados_de_pii():
    achados = scan_file(str(PROTOTIPOS / "corrigido.py"))
    assert [a for a in achados if a["rule_id"] in {"PII_LEAK", "PII_HARDCODED"}] == []
