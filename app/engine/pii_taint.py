"""Taint analysis de PII: rastreia dado pessoal da fonte até saídas inseguras (sinks).

Resumo do modelo (ver docs/cyber/etapa2-taint.md):
- Fonte (source): parâmetro, atributo, chave ou .get() com nome do vocabulário da Zeladoria
  (cpf, telefone, email, senha, descricao...). A análise estática não vê o CONTEÚDO do campo,
  então a fonte é declarada pelo nome (limite assumido).
- Propagação: atribuição, f-string, concatenação, %, .format(), dict/lista, desempacotamento e
  chamadas. Chamada desconhecida repassa o taint com confiança "media" (conservador: para
  privacidade, alerta a mais é preferível a vazamento escondido).
- Sink: log, print, resposta de rota FastAPI, exceção, escrita em arquivo.
- Sanitizador: mask_pii() (e len(), que devolve só o tamanho).
- Escopo: intra-função. Cada ramo de if/try é analisado com cópia do estado e depois unido.
"""
import ast
from dataclasses import dataclass, replace

from app.engine.rules import SecurityIssue
from app.pii.detectors import PII_META

# Nome do campo -> tipo de PII (inferido pelo nome)
FIELD_TYPES = {
    "cpf": "CPF",
    "telefone": "TELEFONE", "celular": "TELEFONE",
    "email": "EMAIL",
    "senha": "SENHA", "password": "SENHA", "token": "SENHA",
    "descricao": "TEXTO_LIVRE", "endereco": "TEXTO_LIVRE", "observacao": "TEXTO_LIVRE",
    "saude": "SAUDE", "laudo": "SAUDE",
}
# Parâmetros que representam o corpo da requisição inteiro (usar o objeto todo vaza todos os campos)
OBJECT_PARAM_NAMES = {"ocorrencia", "usuario", "user", "dados", "payload", "body", "request", "req", "form"}
OBJECT_ANNOTATION_SUFFIXES = ("In", "Create", "Request", "Payload", "Input", "Schema", "Form", "Body")

SANITIZERS = {"mask_pii", "len"}
# Chamadas que transformam o texto mas mantêm o conteúdo: o taint segue com confiança "alta"
PASSTHROUGH = {
    "str", "repr", "ascii", "format", "strip", "lstrip", "rstrip", "lower", "upper", "title",
    "capitalize", "replace", "join", "encode", "decode", "dumps", "model_dump", "dict", "json", "copy",
}
GETTERS = {"get", "pop", "getlist"}

LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log", "fatal"}
LOGGER_NAMES = {"logging", "logger", "log", "LOGGER", "_logger", "_log"}
FILE_METHODS = {"write", "writelines", "writerow", "writerows"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

# Destino -> CWE e peso (o peso do destino alimenta o Risco Cidadão na Etapa 4)
SINK_META = {
    "log": {"cwe": "CWE-532", "weight": 1},          # informação sensível em arquivo de log
    "print": {"cwe": "CWE-532", "weight": 1},        # saída padrão acaba em log de container
    "arquivo": {"cwe": "CWE-312", "weight": 2},      # armazenamento em texto claro
    "excecao": {"cwe": "CWE-209", "weight": 3},      # mensagem de erro com dado sensível
    "resposta_api": {"cwe": "CWE-200", "weight": 3}, # exposição a qualquer cliente da API
}


@dataclass(frozen=True)
class Taint:
    label: str                 # origem legível, ex.: "ocorrencia.telefone"
    pii_type: str
    trace: tuple               # passos do fluxo, ex.: ("ocorrencia.telefone (L12)", "contato (L13)")
    exact: bool = True         # False depois de passar por função desconhecida

    @property
    def weight(self) -> int:
        return PII_META[self.pii_type]["weight"]

    def via(self, step: str, line: int, exact=None):
        item = f"{step} (L{line})"
        trace = self.trace if self.trace and self.trace[-1] == item else self.trace + (item,)
        return replace(self, trace=trace, exact=self.exact if exact is None else exact)


def _merge(parts):
    parts = [p for p in parts if p is not None]
    return max(parts, key=lambda p: p.weight) if parts else None


def _union(a: dict, b: dict) -> dict:
    out = dict(a)
    for name, taint in b.items():
        if name not in out or taint.weight > out[name].weight:
            out[name] = taint
    return out


def _is_route(func) -> bool:
    for dec in func.decorator_list:
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in HTTP_METHODS:
            return True
    return False


def _const_key(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class FunctionPIIAnalyzer:
    def __init__(self, func):
        self.func = func
        self.state: dict[str, Taint] = {}
        self.objects: set[str] = set()
        self.issues = []
        self._seen = set()
        self.is_route = _is_route(func)

    # ------------------------------------------------------------ entrada
    def analyze(self):
        a = self.func.args
        for arg in a.posonlyargs + a.args + a.kwonlyargs:
            name = arg.arg
            if name in ("self", "cls"):
                continue
            if name in FIELD_TYPES:
                src = f"parâmetro {name}"
                self.state[name] = Taint(src, FIELD_TYPES[name], (f"{src} (L{arg.lineno})",))
            elif name in OBJECT_PARAM_NAMES or self._annotated_as_body(arg):
                self.objects.add(name)
        self._visit_body(self.func.body)
        return self.issues

    @staticmethod
    def _annotated_as_body(arg) -> bool:
        ann = arg.annotation
        return isinstance(ann, ast.Name) and ann.id.endswith(OBJECT_ANNOTATION_SUFFIXES)

    # ------------------------------------------------------------ expressões
    def _source(self, node, field):
        label = ast.unparse(node)
        return Taint(label, FIELD_TYPES[field], (f"{label} (L{node.lineno})",))

    def _taint_of(self, node):
        """Devolve o Taint da expressão (ou None se estiver limpa)."""
        if node is None:
            return None
        if isinstance(node, ast.Name):
            if node.id in self.state:
                return self.state[node.id]
            if node.id in self.objects:
                label = f"{node.id} (objeto completo)"
                return Taint(label, "MULTIPLOS", (f"{label} (L{node.lineno})",))
            return None
        if isinstance(node, ast.Attribute):
            if node.attr in FIELD_TYPES:
                return self._source(node, node.attr)
            if isinstance(node.value, ast.Name) and node.value.id in self.objects:
                return None  # campo que não é PII (ex.: ocorrencia.tipo)
            return self._taint_of(node.value)
        if isinstance(node, ast.Subscript):
            key = _const_key(node.slice)
            if key in FIELD_TYPES:
                return self._source(node, key)
            if isinstance(node.value, ast.Name) and node.value.id in self.objects:
                return None
            return self._taint_of(node.value)
        if isinstance(node, ast.JoinedStr):
            return _merge(self._taint_of(v.value) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.BinOp):
            return _merge([self._taint_of(node.left), self._taint_of(node.right)])
        if isinstance(node, ast.BoolOp):
            return _merge(self._taint_of(v) for v in node.values)
        if isinstance(node, ast.IfExp):
            return _merge([self._taint_of(node.body), self._taint_of(node.orelse)])
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _merge(self._taint_of(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return _merge(self._taint_of(v) for v in node.values)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return _merge([self._taint_of(node.elt)] + [self._taint_of(g.iter) for g in node.generators])
        if isinstance(node, ast.DictComp):
            return _merge([self._taint_of(node.value)] + [self._taint_of(g.iter) for g in node.generators])
        if isinstance(node, (ast.Await, ast.Starred, ast.FormattedValue)):
            return self._taint_of(node.value)
        if isinstance(node, ast.Call):
            return self._taint_of_call(node)
        return None  # constantes, comparações, números...

    def _taint_of_call(self, node):
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if name in SANITIZERS:
            return None
        if isinstance(func, ast.Attribute) and func.attr in GETTERS and node.args:
            key = _const_key(node.args[0])
            if key in FIELD_TYPES:  # dados.get("cpf")
                return self._source(node, key)
            if isinstance(func.value, ast.Name) and func.value.id in self.objects:
                return None
        parts = [self._taint_of(func.value)] if isinstance(func, ast.Attribute) else []
        parts += [self._taint_of(a) for a in node.args]
        parts += [self._taint_of(k.value) for k in node.keywords]
        taint = _merge(parts)
        if taint is not None and name not in PASSTHROUGH:
            taint = replace(taint, exact=False)  # função desconhecida: segue contaminado, confiança menor
        return taint

    # ------------------------------------------------------------ sinks
    @staticmethod
    def _sink_kind(call):
        f = call.func
        if isinstance(f, ast.Name):
            if f.id == "print":
                return "print"
            if f.id == "HTTPException":
                return "excecao"
        if isinstance(f, ast.Attribute):
            base = f.value
            base_name = base.id if isinstance(base, ast.Name) else base.attr if isinstance(base, ast.Attribute) else None
            if f.attr == "HTTPException":
                return "excecao"
            if f.attr in LOG_METHODS and base_name in LOGGER_NAMES:
                return "log"
            if f.attr in FILE_METHODS or (f.attr == "dump" and base_name == "json"):
                return "arquivo"
        return None

    def _report(self, node, kind, taint, destino):
        key = (node.lineno, kind, taint.label)
        if key in self._seen:
            return
        self._seen.add(key)
        fluxo = " → ".join(taint.trace + (f"{destino} (L{node.lineno})",))
        self.issues.append(SecurityIssue(
            rule_id="PII_LEAK",
            cwe=SINK_META[kind]["cwe"],
            # Só nomes de campos e variáveis: o valor do dado nunca aparece no relatório.
            message=(f"Dado pessoal ({taint.pii_type}) chega a '{destino}' sem sanitização. "
                     f"Fluxo: {fluxo}. Aplique mask_pii() antes desse destino."),
            line=node.lineno,
            severity="critical",
            pii_type=taint.pii_type,
            confidence="alta" if taint.exact else "media",
            sink=kind,
        ))

    def _check_calls(self, expr):
        if expr is None:
            return
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                kind = self._sink_kind(node)
                if kind:
                    taint = _merge([self._taint_of(a) for a in node.args] +
                                   [self._taint_of(k.value) for k in node.keywords])
                    if taint:
                        self._report(node, kind, taint, f"{ast.unparse(node.func)}()")

    # ------------------------------------------------------------ comandos
    def _assign(self, target, taint, line):
        if isinstance(target, ast.Name):
            if taint:
                self.state[target.id] = taint.via(target.id, line)
            else:
                self.state.pop(target.id, None)  # reatribuição com valor limpo remove o taint
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, taint, line)
        elif isinstance(target, (ast.Attribute, ast.Subscript)) and taint:
            base = target.value
            if isinstance(base, ast.Name):  # d["x"] = cpf  ->  d fica contaminado
                self.state[base.id] = taint.via(base.id, line)

    def _visit_body(self, stmts):
        for st in stmts:
            self._visit_stmt(st)

    def _branches(self, branches):
        """Analisa cada ramo com cópia do estado inicial e une os resultados (conservador)."""
        start = dict(self.state)
        result = dict(start)
        for body in branches:
            self.state = dict(start)
            self._visit_body(body)
            result = _union(result, self.state)
        self.state = result

    def _visit_stmt(self, st):
        if isinstance(st, ast.Assign):
            self._check_calls(st.value)
            taint = self._taint_of(st.value)
            for target in st.targets:
                self._assign(target, taint, st.lineno)
        elif isinstance(st, ast.AnnAssign) and st.value is not None:
            self._check_calls(st.value)
            self._assign(st.target, self._taint_of(st.value), st.lineno)
        elif isinstance(st, ast.AugAssign):
            self._check_calls(st.value)
            before = self.state.get(st.target.id) if isinstance(st.target, ast.Name) else None
            self._assign(st.target, _merge([before, self._taint_of(st.value)]), st.lineno)
        elif isinstance(st, ast.Expr):
            self._check_calls(st.value)
        elif isinstance(st, ast.Return):
            self._check_calls(st.value)
            taint = self._taint_of(st.value)
            if self.is_route and taint:  # só rota HTTP: o retorno vai para o cliente da API
                self._report(st, "resposta_api", taint, "return (resposta da API)")
        elif isinstance(st, ast.Raise):
            self._check_calls(st.exc)
            if isinstance(st.exc, ast.Call):
                taint = _merge([self._taint_of(a) for a in st.exc.args] +
                               [self._taint_of(k.value) for k in st.exc.keywords])
                if taint:
                    self._report(st, "excecao", taint, f"raise {ast.unparse(st.exc.func)}()")
        elif isinstance(st, (ast.If, ast.While)):
            self._check_calls(st.test)
            self._branches([st.body, st.orelse])
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            self._check_calls(st.iter)
            self._assign(st.target, self._taint_of(st.iter), st.lineno)
            self._branches([st.body, []])
            self._visit_body(st.orelse)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                self._check_calls(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, None, st.lineno)
            self._visit_body(st.body)
        elif isinstance(st, ast.Try):
            self._branches([st.body] + [h.body for h in st.handlers] + [st.orelse])
            self._visit_body(st.finalbody)
        # Funções aninhadas são analisadas à parte pelo PIITaintVisitor.


class PIITaintVisitor(ast.NodeVisitor):
    """Aplica a análise a cada função (def e async def) do módulo."""

    def __init__(self):
        self.issues = []

    def _analyze(self, node):
        self.issues.extend(FunctionPIIAnalyzer(node).analyze())
        self.generic_visit(node)

    visit_FunctionDef = _analyze
    visit_AsyncFunctionDef = _analyze
