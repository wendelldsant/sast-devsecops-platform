import os
import tempfile

from fastapi import FastAPI, UploadFile, File, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.engine.parser import scan_file
from app.ai.ollama_client import analyze_issue, build_snippet
from app.api.database import Base, engine, get_db
from app.api.models import ScanResult

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SAST Platform API")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
async def scan_uploaded_file(
    file: UploadFile = File(...),
    use_ai: bool = True,
    db: Session = Depends(get_db),
):
    content = await file.read()
    source_code = content.decode("utf-8", errors="replace")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        issues = scan_file(tmp_path)
    finally:
        os.remove(tmp_path)

    for issue in issues:
        if use_ai:
            snippet = build_snippet(source_code, issue["line"])
            # chamada bloqueante (HTTP + LLM) roda em thread para não travar a API
            ai_result = await run_in_threadpool(analyze_issue, snippet, issue)
            if ai_result:
                issue.update(ai_result)

        db.add(ScanResult(
            filename=file.filename,
            rule_id=issue["rule_id"],
            cwe=issue["cwe"],
            message=issue["message"],
            line=issue["line"],
            severity=issue["severity"],
            ai_severity=issue.get("ai_severity"),
            ai_false_positive=issue.get("ai_false_positive"),
            ai_explanation=issue.get("ai_explanation"),
            ai_remediation=issue.get("ai_remediation"),
        ))
    db.commit()

    return {
        "filename": file.filename,
        "issues_found": len(issues),
        "issues": issues,
    }