import ast
from app.engine.rules import SecurityVisitor
from app.engine.taint import TaintVisitor


def scan_file(filepath: str) -> list[dict]:
    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()

    tree = ast.parse(source_code, filename=filepath)

    visitor = SecurityVisitor()
    visitor.visit(tree)

    taint_visitor = TaintVisitor()
    taint_visitor.visit(tree)

    all_issues = visitor.issues + taint_visitor.issues
    return [issue.to_dict() for issue in all_issues]