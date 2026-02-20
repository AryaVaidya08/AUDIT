from fastapi import FastAPI

app = FastAPI(title="AUDIT")

@app.get("/")
def health():
    return {"status": "AUDIT is running"}