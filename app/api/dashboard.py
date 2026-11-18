from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.api.database import get_db
from app.api.models import ScanResult, ScanRun
from app.risk import RISCO_PONTOS_MAXIMOS, citizen_risk_level, citizen_risk_score, weighted_points

router = APIRouter()

STATIC_DIR = Path(__file__).parent / "static"
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
PII_RULES = {"PII_LEAK", "PII_HARDCODED"}


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


@router.get("/api/dashboard/citizen-risk")
def citizen_risk(db: Session = Depends(get_db)):
    """Risco Cidadão (0 a 100) do estado ATUAL: considera só o último scan de cada arquivo.

    pontos do achado = peso do tipo de PII x peso do destino x peso da confiança (app/risk.py).
    """
    latest_ids = [rid for (rid,) in db.query(func.max(ScanRun.id)).group_by(ScanRun.filename).all()]
    rows = []
    if latest_ids:
        rows = (
            db.query(ScanResult)
            .filter(ScanResult.scan_id.in_(latest_ids), ScanResult.rule_id.in_(PII_RULES))
            .all()
        )

    by_type, by_sink = {}, {}
    total_points, ai_alerts = 0.0, {"ia": 0, "padrao": 0}
    scored = []
    for r in rows:
        pts = weighted_points(r.alert_points, r.confidence)
        total_points += pts
        for bucket, key in ((by_type, r.pii_type or "OUTRO"), (by_sink, r.sink or "codigo")):
            item = bucket.setdefault(key, {"count": 0, "points": 0.0})
            item["count"] += 1
            item["points"] += pts
        ai_alerts[r.alert_source if r.alert_source in ai_alerts else "padrao"] += 1
        scored.append((pts, r))

    score = citizen_risk_score(total_points)
    scored.sort(key=lambda t: (-t[0], t[1].filename or "", t[1].line or 0))

    def ranked(bucket, name):
        return [
            {name: key, "count": v["count"], "points": round(v["points"], 1)}
            for key, v in sorted(bucket.items(), key=lambda kv: -kv[1]["points"])
        ]

    timeline = [
        {
            "scan_id": run.id,
            "filename": run.filename,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "risk_score": run.risk_score,
            "pii_findings": run.pii_findings,
        }
        for run in reversed(
            db.query(ScanRun).filter(ScanRun.risk_score.isnot(None)).order_by(ScanRun.id.desc()).limit(20).all()
        )
    ]

    return {
        "risk": {
            "score": score,
            "level": citizen_risk_level(score),
            "points": round(total_points, 1),
            "max_points": RISCO_PONTOS_MAXIMOS,
            "files": len(latest_ids),
            "findings": len(rows),
        },
        "ai_alerts": ai_alerts,
        "by_type": ranked(by_type, "pii_type"),
        "by_sink": ranked(by_sink, "sink"),
        "timeline": timeline,
        "top_findings": [
            {
                "filename": r.filename, "line": r.line, "rule_id": r.rule_id, "pii_type": r.pii_type,
                "sink": r.sink, "confidence": r.confidence, "points": round(pts, 1), "level": r.alert_level,
                "alert_title": r.alert_title, "alert_risk": r.alert_risk, "alert_action": r.alert_action,
                "alert_source": r.alert_source,
            }
            for pts, r in scored[:10]
        ],
    }
