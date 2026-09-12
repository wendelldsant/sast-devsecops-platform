from fastapi import FastAPI

app = FastAPI(title="SAST Platform API")

@app.get("/health")
def health_check():
    return {"status": "ok"}