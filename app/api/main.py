import os
import tempfile

from fastapi import FastAPI, UploadFile, File, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.engine.parser import scan_file
from app.ai.citizen_alert import build_citizen_alert
from app.ai.ollama_client import analyze_issue, build_snippet
from app.api.database import Base, engine, ensure_columns, get_db
from app.api.models import ScanResult, ScanRun
from app.api.dashboard import router as dashboard_router
from app.risk import citizen_risk_level, citizen_risk_score, weighted_points

Base.metadata.create_all(bind=engine)
ensure_columns(engine)

PII_RULES = {"PII_LEAK", "PII_HARDCODED"}

app = FastAPI(title="SAST Platform API")
app.include_router(dashboard_router)


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

    run = ScanRun(filename=file.filename, issues_found=len(issues))
    db.add(run)
    db.flush()  # gera o id da execução, que liga os achados ao scan
    pii_points, pii_count = 0.0, 0

    for issue in issues:
        # Achados de PII nunca mandam o trecho de código ao LLM: a linha pode conter a própria PII.
        if use_ai and issue["rule_id"] not in PII_RULES:
            snippet = build_snippet(source_code, issue["line"])
            # chamada bloqueante (HTTP + LLM) roda em thread para não travar a API
            ai_result = await run_in_threadpool(analyze_issue, snippet, issue)
            if ai_result:
                issue.update(ai_result)

        alert = await run_in_threadpool(build_citizen_alert, issue, use_ai)
        issue["citizen_alert"] = alert

        if issue["rule_id"] in PII_RULES:
            pii_count += 1
            pii_points += weighted_points(alert["pontos"], issue.get("confidence"))

        db.add(ScanResult(
            scan_id=run.id,
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
            pii_type=issue.get("pii_type"),
            sink=issue.get("sink"),
            confidence=issue.get("confidence"),
            alert_title=alert["titulo"],
            alert_risk=alert["risco"],
            alert_action=alert["o_que_fazer"],
            alert_level=alert["nivel"],
            alert_points=alert["pontos"],
            alert_source=alert["fonte"],
        ))
    run.pii_findings = pii_count
    run.risk_points = pii_points
    run.risk_score = citizen_risk_score(pii_points)
    db.commit()

    return {
        "filename": file.filename,
        "issues_found": len(issues),
        "citizen_risk": {
            "score": run.risk_score,
            "nivel": citizen_risk_level(run.risk_score),
            "pontos": round(pii_points, 1),
        },
        "issues": issues,
    }