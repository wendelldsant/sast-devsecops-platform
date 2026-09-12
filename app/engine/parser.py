import ast
from app.engine.rules import SecurityVisitor


def scan_file(filepath: str) -> list[dict]:
    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()

    tree = ast.parse(source_code, filename=filepath)

    visitor = SecurityVisitor()
    visitor.visit(tree)

    return [issue.to_dict() for issue in visitor.issues]