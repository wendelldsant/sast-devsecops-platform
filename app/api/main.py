import os
import tempfile
from fastapi import FastAPI, UploadFile, File
from app.engine.parser import scan_file

app = FastAPI(title="SAST Platform API")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
async def scan_uploaded_file(file: UploadFile = File(...)):
    # Salva o arquivo enviado temporariamente para o parser conseguir ler
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        issues = scan_file(tmp_path)
    finally:
        os.remove(tmp_path)  # limpa o arquivo temporário, mesmo se der erro

    return {
        "filename": file.filename,
        "issues_found": len(issues),
        "issues": issues,
    }