"""Protótipo da Zeladoria do Bairro COM vazamentos de PII de propósito.

É o alvo da auditoria SAST da Etapa 2. Os números abaixo são FICTÍCIOS.
Cada comentário "Vazamento N" marca um fluxo que o taint de PII deve apontar.
"""
import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Zeladoria do Bairro (protótipo vulnerável)")
logger = logging.getLogger("zeladoria")

CPF_DEMO = "529.982.247-25"  # PII fixa no código (regra PII_HARDCODED, Etapa 1)
OCORRENCIAS = []


class OcorrenciaIn(BaseModel):
    tipo: str
    descricao: str
    telefone: str | None = None
    cpf: str | None = None


@app.post("/ocorrencias")
def criar_ocorrencia(ocorrencia: OcorrenciaIn):
    # Vazamento 1 (log): a descrição é texto livre e pode trazer CPF, telefone ou saúde
    logger.info(f"Nova ocorrência: {ocorrencia.descricao}")

    # Vazamento 2 (print): o telefone passa por uma variável antes de chegar ao console
    contato = ocorrencia.telefone
    print("Contato do morador:", contato)

    # Vazamento 3 (arquivo): trilha de auditoria gravada com CPF em texto claro
    with open("auditoria.txt", "a", encoding="utf-8") as arquivo:
        arquivo.write(f"{ocorrencia.tipo};{ocorrencia.cpf}\n")

    OCORRENCIAS.append(ocorrencia.model_dump())

    # Vazamento 4 (resposta da API): devolve o CPF para quem chamar
    return {"id": len(OCORRENCIAS), "status": "Aberta", "cpf": ocorrencia.cpf}


@app.post("/login")
def login(email: str, senha: str):
    if senha != "esperada":
        # Vazamento 5 (exceção): a senha digitada volta na mensagem de erro
        raise HTTPException(status_code=401, detail=f"Senha incorreta: {senha}")
    return {"status": "ok"}
