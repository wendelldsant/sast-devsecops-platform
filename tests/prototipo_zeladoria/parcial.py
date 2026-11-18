"""Zeladoria do Bairro com correção PARCIAL: log, print, arquivo e o CPF fixo foram corrigidos.

Ainda vazam: o CPF na resposta da API e a senha na mensagem de erro. Serve para mostrar o
Risco Cidadão caindo por etapas no dashboard (vulnerável -> parcial -> corrigido).
"""
import logging
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.pii import mask_pii

app = FastAPI(title="Zeladoria do Bairro (protótipo parcialmente corrigido)")
logger = logging.getLogger("zeladoria")

SENHA_ESPERADA = os.getenv("ZELADORIA_SENHA_DEMO", "")
OCORRENCIAS = []


class OcorrenciaIn(BaseModel):
    tipo: str
    descricao: str
    telefone: str | None = None
    cpf: str | None = None


@app.post("/ocorrencias")
def criar_ocorrencia(ocorrencia: OcorrenciaIn):
    logger.info(mask_pii(f"Nova ocorrência: {ocorrencia.descricao}"))

    contato = mask_pii(ocorrencia.telefone or "")
    logger.info("Contato do morador: %s", contato)

    with open("auditoria.txt", "a", encoding="utf-8") as arquivo:
        arquivo.write(mask_pii(f"{ocorrencia.tipo};{ocorrencia.cpf}") + "\n")

    OCORRENCIAS.append(ocorrencia.model_dump())

    # Ainda vaza: o CPF volta na resposta da API
    return {"id": len(OCORRENCIAS), "status": "Aberta", "cpf": ocorrencia.cpf}


@app.post("/login")
def login(email: str, senha: str):
    if senha != SENHA_ESPERADA:
        # Ainda vaza: a senha digitada volta na mensagem de erro
        raise HTTPException(status_code=401, detail=f"Senha incorreta: {senha}")
    return {"status": "ok"}
