import ast

from app.pii import find_pii


class SecurityIssue:
    def __init__(self, rule_id, cwe, message, line, severity, pii_type=None, confidence=None):
        self.rule_id = rule_id
        self.cwe = cwe
        self.message = message
        self.line = line
        self.severity = severity
        self.pii_type = pii_type  # só nas regras de PII
        self.confidence = confidence

    def to_dict(self):
        data = {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "message": self.message,
            "line": self.line,
            "severity": self.severity,
        }
        if self.pii_type:
            data["pii_type"] = self.pii_type
            data["confidence"] = self.confidence
        return data


DANGEROUS_FUNCTIONS = {"eval", "exec"}
SENSITIVE_VAR_NAMES = {"password", "senha", "secret", "api_key", "token"}
# Em literais de código só entram tipos de alta precisão. Saúde fica de fora: um literal como
# "doença" em uma mensagem de erro geraria falso positivo. Saúde é tratada no modo texto (ocorrências).
CODE_PII_TYPES = {"CPF", "EMAIL", "TELEFONE", "SENHA"}


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        # Regra 1: uso de eval() ou exec()
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_FUNCTIONS:
            self.issues.append(SecurityIssue(
                rule_id="DANGEROUS_FUNCTION",
                cwe="CWE-95",
                message=f"Uso perigoso de '{node.func.id}()' pode permitir execução de código arbitrário.",
                line=node.lineno,
                severity="critical",
            ))

        # Regra 3: subprocess com shell=True
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"run", "call", "Popen"}:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.issues.append(SecurityIssue(
                        rule_id="SHELL_INJECTION",
                        cwe="CWE-78",
                        message="Uso de 'shell=True' em subprocess pode permitir injeção de comandos.",
                        line=node.lineno,
                        severity="high",
                    ))

        self.generic_visit(node)  # continua percorrendo os nós filhos

    def visit_Expr(self, node):
        # Strings soltas (docstrings) documentam o código e não são dados em uso: não analisar.
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return
        self.generic_visit(node)

    def visit_Constant(self, node):
        # Regra 4: dado pessoal ou credencial dentro de um literal de texto
        if isinstance(node.value, str):
            for match in find_pii(node.value, CODE_PII_TYPES):
                self.issues.append(SecurityIssue(
                    rule_id="PII_HARDCODED",
                    cwe=match.cwe,
                    # O valor encontrado NUNCA entra na mensagem: o relatório não pode vazar a PII.
                    message=(f"Dado pessoal ({match.pii_type}) fixo no código, confiança {match.confidence}. "
                             "O valor não é exibido neste relatório."),
                    line=node.lineno,
                    severity=match.severity,
                    pii_type=match.pii_type,
                    confidence=match.confidence,
                ))

    def visit_Assign(self, node):
        # Regra 2: senha/token hardcoded
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in SENSITIVE_VAR_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.issues.append(SecurityIssue(
                        rule_id="HARDCODED_SECRET",
                        cwe="CWE-798",
                        message=f"Valor sensível hardcoded na variável '{target.id}'.",
                        line=node.lineno,
                        severity="high",
                    ))

        self.generic_visit(node)