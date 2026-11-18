from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float
from sqlalchemy.sql import func
from app.api.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    rule_id = Column(String)
    cwe = Column(String)
    message = Column(String)
    line = Column(Integer)
    severity = Column(String, index=True)
    ai_severity = Column(String, nullable=True)
    ai_false_positive = Column(Boolean, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    # Etapa 3 (Cybersecurity): achados de PII e alerta ao cidadão
    pii_type = Column(String, nullable=True)
    sink = Column(String, nullable=True)
    confidence = Column(String, nullable=True)
    alert_title = Column(String, nullable=True)
    alert_risk = Column(Text, nullable=True)
    alert_action = Column(Text, nullable=True)
    alert_level = Column(String, nullable=True)
    alert_points = Column(Integer, nullable=True)
    alert_source = Column(String, nullable=True)  # "ia" ou "padrao"
    scan_id = Column(Integer, index=True, nullable=True)  # execução (scan_runs) que gerou o achado
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanRun(Base):
    """Uma execução do /scan. Existe mesmo sem achados, para o Risco Cidadão cair a 0 depois da correção."""
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    issues_found = Column(Integer, default=0)
    pii_findings = Column(Integer, default=0)
    risk_points = Column(Float, default=0.0)
    risk_score = Column(Integer, nullable=True)  # Risco Cidadão (0 a 100) desta execução
    created_at = Column(DateTime(timezone=True), server_default=func.now())
