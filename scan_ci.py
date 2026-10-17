"""Scanner SAST em linha de comando, usado como Security Gate no CI/CD."""
import argparse
import json
import os
import sys
from pathlib import Path

from app.engine.parser import scan_file

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_EXCLUDES = {".git", ".venv", "venv", "__pycache__", "node_modules"}


def collect_files(paths, excludes):
    found = set()
    for raw in paths:
        path = Path(raw)
        if path.is_file() and path.suffix == ".py":
            found.add(path)
        elif path.is_dir():
            found.update(path.rglob("*.py"))

    def is_excluded(file_path: Path) -> bool:
        if DEFAULT_EXCLUDES.intersection(file_path.parts):
            return True
        posix = file_path.as_posix()
        return any(posix == ex or posix.startswith(ex.rstrip("/") + "/") for ex in excludes)

    return sorted(f for f in found if not is_excluded(f))


def write_step_summary(findings, errors, files_count, fail_on, blocking_count):
    """Escreve um resumo em Markdown na aba 'Summary' do job no GitHub Actions."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    status = "❌ Bloqueado" if blocking_count else "✅ Aprovado"
    lines = [
        "## 🛡️ SAST Security Gate",
        f"**Resultado:** {status} (bloqueia a partir de severidade `{fail_on}`)",
        f"**Arquivos analisados:** {files_count} | **Violações:** {len(findings)} | "
        f"**Bloqueantes:** {blocking_count}",
        "",
    ]
    if findings:
        lines += ["| Severidade | Arquivo | Linha | Regra | CWE |", "|---|---|---|---|---|"]
        for i in sorted(findings, key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0)):
            lines.append(
                f"| {i['severity']} | `{i['file']}` | {i['line']} | {i['rule_id']} | {i['cwe']} |"
            )
    if errors:
        lines += ["", "**Arquivos que não puderam ser analisados:**"]
        lines += [f"- `{e['file']}`: {e['error']}" for e in errors]

    with open(summary_path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="SAST Security Gate")
    parser.add_argument("paths", nargs="+", help="arquivos ou pastas a analisar")
    parser.add_argument("--exclude", action="append", default=[], help="pasta/arquivo a ignorar")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="critical",
                        help="severidade mínima que bloqueia (padrão: critical)")
    parser.add_argument("--report", default="sast-report.json", help="arquivo do relatório JSON")
    args = parser.parse_args()

    files = collect_files(args.paths, args.exclude)
    findings, errors = [], []

    for file_path in files:
        try:
            for issue in scan_file(str(file_path)):
                issue["file"] = file_path.as_posix()
                findings.append(issue)
        except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
            errors.append({"file": file_path.as_posix(), "error": f"{type(exc).__name__}: {exc}"})

    threshold = SEVERITY_ORDER[args.fail_on]
    blocking = [i for i in findings if SEVERITY_ORDER.get(i["severity"], 0) >= threshold]

    in_github = os.getenv("GITHUB_ACTIONS") == "true"
    for i in findings:
        is_blocking = i in blocking
        if in_github:
            level = "error" if is_blocking else "warning"
            print(f"::{level} file={i['file']},line={i['line']},"
                  f"title={i['rule_id']} ({i['cwe']})::{i['message']}")
        else:
            print(f"[{i['severity'].upper():8}] {i['file']}:{i['line']}  "
                  f"{i['rule_id']} ({i['cwe']}) - {i['message']}")

    report = {
        "scanned_files": len(files),
        "fail_on": args.fail_on,
        "total_findings": len(findings),
        "blocking_findings": len(blocking),
        "passed": not blocking,
        "findings": findings,
        "errors": errors,
    }
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    write_step_summary(findings, errors, len(files), args.fail_on, len(blocking))

    print(f"\nArquivos analisados: {len(files)} | Violações: {len(findings)} | "
          f"Bloqueantes (>= {args.fail_on}): {len(blocking)}")
    if blocking:
        print("SECURITY GATE: REPROVADO")
        sys.exit(1)
    print("SECURITY GATE: APROVADO")


if __name__ == "__main__":
    main()