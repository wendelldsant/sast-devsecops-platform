import ast
from app.engine.rules import SecurityIssue

# Conversões explícitas de tipo tratadas como sanitização básica no MVP
SANITIZING_CALLS = {"int", "float", "bool"}

# Sinks reconhecidos: função direta (eval/exec) ou atributo de módulo (os.system)
DIRECT_SINKS = {"eval": "CWE-95", "exec": "CWE-95"}
OS_SINKS = {"system": "CWE-78", "popen": "CWE-78"}


class FunctionTaintAnalyzer:
    """
    Analisa uma única função em busca de dado não confiável (taint) que flui,
    sem sanitização, até uma função sensível (sink).

    Fontes reconhecidas (MVP):
      - Parâmetros da função
      - Retorno de input()

    Sanitização reconhecida (MVP):
      - Conversão explícita de tipo (int(), float(), bool())
    """

    def __init__(self, func_node: ast.FunctionDef):
        self.func_node = func_node
        self.tainted_vars = set()
        self.issues = []

    def analyze(self):
        # Parâmetros da função são tratados como fonte não confiável
        for arg in self.func_node.args.args:
            self.tainted_vars.add(arg.arg)

        for node in ast.walk(self.func_node):
            if isinstance(node, ast.Assign):
                self._handle_assignment(node)
            elif isinstance(node, ast.Call):
                self._handle_call(node)

        return self.issues

    def _handle_assignment(self, node: ast.Assign):
        if not isinstance(node.value, ast.Call):
            # Propagação simples: var_b = var_a (contamina var_b se var_a já for tainted)
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
            return

        if not isinstance(node.value.func, ast.Name):
            return

        called_name = node.value.func.id
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if called_name == "input":
                self.tainted_vars.add(target.id)
            elif called_name in SANITIZING_CALLS:
                self.tainted_vars.discard(target.id)

    def _handle_call(self, node: ast.Call):
        func = node.func

        if isinstance(func, ast.Name) and func.id in DIRECT_SINKS:
            self._check_args_for_taint(node, f"{func.id}()", DIRECT_SINKS[func.id])

        if isinstance(func, ast.Attribute) and func.attr in OS_SINKS:
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                self._check_args_for_taint(node, f"os.{func.attr}()", OS_SINKS[func.attr])

    def _check_args_for_taint(self, node: ast.Call, sink_name: str, cwe: str):
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                self.issues.append(SecurityIssue(
                    rule_id="TAINTED_DATA_FLOW",
                    cwe=cwe,
                    message=(
                        f"Dado não confiável (parâmetro/input) atinge '{sink_name}' "
                        f"através da variável '{arg.id}' sem validação ou sanitização."
                    ),
                    line=node.lineno,
                    severity="critical",
                ))


class TaintVisitor(ast.NodeVisitor):
    """Percorre o módulo inteiro, aplicando a análise de taint em cada função encontrada."""

    def __init__(self):
        self.issues = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        analyzer = FunctionTaintAnalyzer(node)
        self.issues.extend(analyzer.analyze())
        self.generic_visit(node)