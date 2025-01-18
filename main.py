import os
from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/api/ping")
def send():
    return {"status": "ok"}

if __name__ == "__main__":
    server_address = os.getenv("SERVER_ADDRESS", "0.0.0.0:8080")
    host, port = server_address.split(":")
    uvicorn.run(app, host=host, port=int(port))
