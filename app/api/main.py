import os
import tempfile
from fastapi import FastAPI, UploadFile, File, Depends
from sqlalchemy.orm import Session
from app.engine.parser import scan_file
from app.api.database import Base, engine, get_db
from app.api.models import ScanResult

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SAST Platform API")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
async def scan_uploaded_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        issues = scan_file(tmp_path)
    finally:
        os.remove(tmp_path)

    for issue in issues:
        db_issue = ScanResult(
            filename=file.filename,
            rule_id=issue["rule_id"],
            cwe=issue["cwe"],
            message=issue["message"],
            line=issue["line"],
            severity=issue["severity"],
        )
        db.add(db_issue)
    db.commit()

    return {
        "filename": file.filename,
        "issues_found": len(issues),
        "issues": issues,
    }