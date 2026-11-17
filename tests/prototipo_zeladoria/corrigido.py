"""Mesma Zeladoria do Bairro, corrigida: nenhum dado pessoal chega a saídas inseguras."""
import logging
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.pii import mask_pii

app = FastAPI(title="Zeladoria do Bairro (protótipo corrigido)")
logger = logging.getLogger("zeladoria")

SENHA_ESPERADA = os.getenv("ZELADORIA_SENHA_DEMO", "")  # segredo vem do ambiente, não do código
OCORRENCIAS = []


class OcorrenciaIn(BaseModel):
    tipo: str
    descricao: str
    telefone: str | None = None
    cpf: str | None = None


@app.post("/ocorrencias")
def criar_ocorrencia(ocorrencia: OcorrenciaIn):
    # Correção 1: texto livre mascarado antes do log
    logger.info(mask_pii(f"Nova ocorrência: {ocorrencia.descricao}"))

    # Correção 2: logger no lugar de print, com o telefone mascarado
    contato = mask_pii(ocorrencia.telefone or "")
    logger.info("Contato do morador: %s", contato)

    # Correção 3: o arquivo de auditoria recebe só o tipo e o CPF mascarado
    with open("auditoria.txt", "a", encoding="utf-8") as arquivo:
        arquivo.write(mask_pii(f"{ocorrencia.tipo};{ocorrencia.cpf}") + "\n")

    OCORRENCIAS.append(ocorrencia.model_dump())

    # Correção 4: a resposta traz só o necessário (minimização de dados)
    return {"id": len(OCORRENCIAS), "status": "Aberta"}


@app.post("/login")
def login(email: str, senha: str):
    if senha != SENHA_ESPERADA:
        # Correção 5: mensagem genérica, sem devolver o que o usuário digitou
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    return {"status": "ok"}
