from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import time
import logging

# Database
from app.core.database import engine, Base
from app.models import db_models

# Routes
from app.api.routes import (
    osint,
    shodan,
    abuseipdb,
    virustotal,
    auth,
    threat_intel,
<<<<<<< HEAD
    analytics,
    alerts
=======
    analytics
>>>>>>> d0f073da67d0618f343f8ec0c7a223c3526914d5
)

from app.api.routes.email import router as email_router

# ---------------------------------------------------
# Logging Configuration
# ---------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("CyberGita")

# ---------------------------------------------------
# Database Initialization
# ---------------------------------------------------

Base.metadata.create_all(bind=engine)

# ---------------------------------------------------
# FastAPI App
# ---------------------------------------------------

app = FastAPI(
    title="Cyber Gita OSINT Platform",
    description="Professional AI-powered OSINT & Threat Intelligence Platform",
    version="1.0.0"
)

# ---------------------------------------------------
# CORS Configuration
# ---------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------
# Request Logging Middleware
# ---------------------------------------------------

@app.middleware("http")
async def log_requests(request: Request, call_next):

    start_time = time.time()

    response = await call_next(request)

    process_time = round(time.time() - start_time, 4)

    logger.info(
        f"{request.method} {request.url.path} | "
        f"Status: {response.status_code} | "
        f"Time: {process_time}s"
    )

    response.headers["X-Process-Time"] = str(process_time)

    return response

# ---------------------------------------------------
# API Routes
# ---------------------------------------------------

app.include_router(
    auth.router,
    prefix="/api/auth",
    tags=["Authentication"]
)

app.include_router(
    osint.router,
    prefix="/api/osint",
    tags=["OSINT"]
)

app.include_router(
    shodan.router,
    prefix="/api/shodan",
    tags=["Shodan"]
)

app.include_router(
    abuseipdb.router,
    prefix="/api/abuseipdb",
    tags=["AbuseIPDB"]
)

app.include_router(
    virustotal.router,
    prefix="/api/virustotal",
    tags=["VirusTotal"]
)

app.include_router(
    threat_intel.router,
    prefix="/api/threat-intel",
    tags=["Threat Intelligence"]
)

app.include_router(
    analytics.router,
    prefix="/api/analytics",
    tags=["Analytics"]
)

<<<<<<< HEAD
app.include_router(
    alerts.router,
    prefix="/api/alerts",
    tags=["Alerts"]
)

=======
>>>>>>> d0f073da67d0618f343f8ec0c7a223c3526914d5
# Email Intelligence Route
app.include_router(
    email_router,
    prefix="/api/email",
    tags=["Email Intelligence"]
)

# ---------------------------------------------------
# Root Endpoint
# ---------------------------------------------------

@app.get("/")
def home():

    return {
        "platform": "Cyber Gita OSINT",
        "status": "online",
        "version": "1.0.0",
        "message": "Backend running successfully"
    }

# ---------------------------------------------------
# Health Check
# ---------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "database": "connected",
        "server": "running"
    }