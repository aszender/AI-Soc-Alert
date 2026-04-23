"""AI SOC Alert Investigator — FastAPI application."""
from fastapi import FastAPI
from .api.routes import router

app = FastAPI(
    title="AI SOC Alert Investigator",
    description="Multi-agent AI system for autonomous security alert investigation",
    version="1.0.0",
)
app.include_router(router)
