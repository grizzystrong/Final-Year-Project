from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import your ML modules here later
# from core import ids_model, policy_engine

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows your GitHub Pages site to connect
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api")
def health_check():
    return {"status": "Backend is active", "model": "Zero Trust IoT IPS"}