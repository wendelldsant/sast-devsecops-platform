from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.api.database import get_db
from app.api.models import ScanResult

router = APIRouter()

STATIC_DIR = Path(__file__).parent / "static"
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


@router.get("/dashboard", include_in_schema=False)
def dashboard_page():
    """Serve a página do dashboard executivo."""
    return FileResponse(STATIC_DIR / "dashboard.html")


@router.get("/api/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    """Métricas agregadas a partir do histórico de scans salvo no PostgreSQL."""
    total = db.query(func.count(ScanResult.id)).scalar() or 0

    # Distribuição por severidade (severidade definida pelas regras)
    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for severity, count in (
        db.query(ScanResult.severity, func.count(ScanResult.id))
        .group_by(ScanResult.severity)
        .all()
    ):
        by_severity[severity] = count

    # Tendência: violações registradas por semana
    week = func.date_trunc("week", ScanResult.created_at)
    trend = [
        {"period": period.date().isoformat(), "count": count}
        for period, count in (
            db.query(week, func.count(ScanResult.id)).group_by(week).order_by(week).all()
        )
    ]

    # Top 5 arquivos com mais violações
    critical_sum = func.sum(case((ScanResult.severity == "critical", 1), else_=0))
    top_files = [
        {"filename": filename, "total": count, "critical": int(critical or 0)}
        for filename, count, critical in (
            db.query(ScanResult.filename, func.count(ScanResult.id), critical_sum)
            .group_by(ScanResult.filename)
            .order_by(func.count(ScanResult.id).desc())
            .limit(5)
            .all()
        )
    ]

    # Indicadores gerais
    distinct_files = db.query(func.count(func.distinct(ScanResult.filename))).scalar() or 0
    ai_false_positives = (
        db.query(func.count(ScanResult.id)).filter(ScanResult.ai_false_positive.is_(True)).scalar()
        or 0
    )

    # Últimas violações, com a análise da IA
    latest_findings = [
        {
            "filename": r.filename,
            "line": r.line,
            "rule_id": r.rule_id,
            "cwe": r.cwe,
            "severity": r.severity,
            "ai_severity": r.ai_severity,
            "ai_false_positive": r.ai_false_positive,
            "ai_explanation": r.ai_explanation,
            "ai_remediation": r.ai_remediation,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in db.query(ScanResult).order_by(ScanResult.id.desc()).limit(10).all()
    ]

    return {
        "kpis": {
            "total": total,
            "critical": by_severity.get("critical", 0),
            "files": distinct_files,
            "ai_false_positives": ai_false_positives,
        },
        "by_severity": by_severity,
        "trend": trend,
        "top_files": top_files,
        "latest_findings": latest_findings,
    }