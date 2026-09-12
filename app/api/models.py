from sqlalchemy import Column, Integer, String, DateTime
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())