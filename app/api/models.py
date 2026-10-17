from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())