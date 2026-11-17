"""Testes do módulo de PII. Todos os dados são FICTÍCIOS.

Rodar da raiz do repositório:  python -m pytest tests/test_pii.py -v
"""
from app.engine.parser import scan_file
from app.pii import find_pii, is_valid_cpf, mask_pii

CPF_OK = "529.982.247-25"      # válido pelo dígito verificador, mas fictício
CPF_OK_RAW = "52998224725"
CPF_BAD_DV = "529.982.247-26"
CPF_REPEATED = "111.111.111-11"


def types(text, **kw):
    return [(m.pii_type, m.confidence) for m in find_pii(text, **kw)]


# ---------------------------------------------------------------- CPF
def test_cpf_dv_valido_e_invalido():
    assert is_valid_cpf(CPF_OK)
    assert not is_valid_cpf(CPF_BAD_DV)


def test_cpf_sequencia_repetida_rejeitada():
    assert not is_valid_cpf(CPF_REPEATED)
    assert types(f"cpf {CPF_REPEATED}") == []


def test_cpf_com_mascara_tem_confianca_alta():
    assert types(f"Meu CPF é {CPF_OK} e moro na Rua A") == [("CPF", "alta")]


def test_cpf_so_digitos_com_palavra_cpf_e_alta():
    assert types(f"cpf: {CPF_OK_RAW}") == [("CPF", "alta")]


def test_cpf_so_digitos_sem_contexto_e_media():
    assert types(f"documento {CPF_OK_RAW}") == [("CPF", "media")]


def test_cpf_com_dv_errado_nao_e_detectado():
    assert types(f"protocolo {CPF_BAD_DV}") == []


# ---------------------------------------------------------------- Telefone
def test_telefone_formatado_alta():
    assert types("ligue (11) 91234-5678") == [("TELEFONE", "alta")]
    assert types("+55 11 91234-5678") == [("TELEFONE", "alta")]
    assert types("fixo 11 3456-7890") == [("TELEFONE", "alta")]


def test_telefone_so_digitos_exige_contexto():
    assert types("whats 11912345678") == [("TELEFONE", "media")]
    assert types("protocolo 11912345678") == []  # número solto: ignorado de propósito


def test_telefone_ddd_invalido_ignorado():
    assert types("(10) 91234-5678") == []


def test_protocolo_nao_vira_pii():
    assert types("Chamado SP-2026-0012345 aberto em 16/11/2026") == []
    assert types("protocolo 20261116123") == []


# ---------------------------------------------------------------- E-mail
def test_email():
    assert types("escreva para maria.teste@exemplo.com.br") == [("EMAIL", "alta")]


# ---------------------------------------------------------------- Senha
def test_senha_mascara_so_o_valor():
    texto = "a senha do wifi é abc12345"
    assert types(texto) == [("SENHA", "alta")]
    assert mask_pii(texto) == "a senha do wifi é [SENHA]"


def test_senha_ignora_none_e_texto_ja_mascarado():
    assert types("token = None") == []
    assert types("senha: [SENHA]") == []


# ---------------------------------------------------------------- Saúde
def test_saude_com_contexto_pessoal():
    assert types("eu tenho diabetes e preciso de acesso") == [("SAUDE", "media")]
    assert types("minha mãe faz tratamento de câncer") == [("SAUDE", "media")]
    assert types("laudo CID F32.1") == [("SAUDE", "alta")]


def test_saude_controle_de_falso_positivo():
    assert types("foco de dengue na esquina") == []
    assert types("calçada ruim para cadeirante") == []
    assert types("o poste está em frente ao hospital") == []


# ---------------------------------------------------------------- Mascaramento
def test_mascara_remove_todos_os_valores():
    texto = f"Sou João, CPF {CPF_OK}, tel (11) 91234-5678, joao@exemplo.com. Tenho diabetes."
    mascarado = mask_pii(texto)
    for valor in (CPF_OK, "91234-5678", "joao@exemplo.com", "diabetes"):
        assert valor not in mascarado
    assert mascarado == "Sou João, CPF [CPF], tel [TELEFONE], [EMAIL]. Tenho [SAUDE]."


def test_mascara_e_idempotente():
    texto = f"CPF {CPF_OK} senha: abc12345"
    uma_vez = mask_pii(texto)
    assert find_pii(uma_vez) == []
    assert mask_pii(uma_vez) == uma_vez


def test_sobreposicao_telefone_vence_cpf_no_empate():
    # 11 dígitos que parecem celular e passam no DV de CPF, com contexto de telefone
    m = find_pii("tel 11912345678")
    assert [x.pii_type for x in m] == ["TELEFONE"]


# ---------------------------------------------------------------- Regra no motor SAST
def _scan_source(tmp_path, source):
    path = tmp_path / "amostra.py"
    path.write_text(source, encoding="utf-8")
    return scan_file(str(path))


def test_regra_pii_hardcoded_detecta_cpf_em_literal(tmp_path):
    issues = _scan_source(tmp_path, f'def f():\n    print("CPF {CPF_OK}")\n')
    pii = [i for i in issues if i["rule_id"] == "PII_HARDCODED"]
    assert len(pii) == 1
    assert pii[0]["pii_type"] == "CPF" and pii[0]["line"] == 2
    assert pii[0]["severity"] == "high"


def test_relatorio_do_scanner_nao_vaza_o_valor(tmp_path):
    issues = _scan_source(tmp_path, f'x = "CPF {CPF_OK} tel (11) 91234-5678"\n')
    texto = str(issues)
    assert CPF_OK not in texto and "91234-5678" not in texto


def test_docstring_nao_e_analisada(tmp_path):
    issues = _scan_source(tmp_path, f'def f():\n    """Exemplo: CPF {CPF_OK}"""\n    return 1\n')
    assert [i for i in issues if i["rule_id"] == "PII_HARDCODED"] == []


def test_saude_nao_e_checada_em_literal_de_codigo(tmp_path):
    issues = _scan_source(tmp_path, 'msg = "paciente tem diabetes"\n')
    assert [i for i in issues if i["rule_id"] == "PII_HARDCODED"] == []


def test_regras_antigas_continuam_funcionando(tmp_path):
    issues = _scan_source(tmp_path, 'def f(x):\n    eval(x)\n')
    assert {i["rule_id"] for i in issues} >= {"DANGEROUS_FUNCTION", "TAINTED_DATA_FLOW"}
