import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Colunas da Etapa 3. create_all() não altera tabelas já criadas, então adicionamos o que faltar.
NEW_COLUMNS = {
    "pii_type": "VARCHAR", "sink": "VARCHAR", "confidence": "VARCHAR",
    "alert_title": "VARCHAR", "alert_risk": "TEXT", "alert_action": "TEXT",
    "alert_level": "VARCHAR", "alert_points": "INTEGER", "alert_source": "VARCHAR",
    "scan_id": "INTEGER",
}


def ensure_columns(db_engine):
    """Migração idempotente: adiciona em scan_results as colunas que ainda não existem."""
    inspector = inspect(db_engine)
    if "scan_results" not in inspector.get_table_names():
        return []
    existing = {c["name"] for c in inspector.get_columns("scan_results")}
    added = []
    with db_engine.begin() as conn:
        for name, ddl in NEW_COLUMNS.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE scan_results ADD COLUMN {name} {ddl}"))
                added.append(name)
    return added
