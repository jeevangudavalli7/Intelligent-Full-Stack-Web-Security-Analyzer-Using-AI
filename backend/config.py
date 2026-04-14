"""
Configuration settings for the Security Analyzer application
"""
import os
from datetime import timedelta
from typing import Optional

# Security settings
SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

# Database settings
DATABASE_URL: str = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./security_analyzer.db"
)

# Redis settings (for Celery)
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Celery settings
CELERY_BROKER_URL: str = REDIS_URL
CELERY_RESULT_BACKEND: str = REDIS_URL

# ML Model settings
ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "models/vulnerability_classifier.pkl")
ML_CONFIDENCE_THRESHOLD: float = float(os.getenv("ML_CONFIDENCE_THRESHOLD", "0.75"))

# Scanner settings
SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "300"))
MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))

# API settings
API_RATE_LIMIT: int = int(os.getenv("API_RATE_LIMIT", "100"))
API_RATE_LIMIT_PERIOD: int = 60  # seconds

# CORS settings
CORS_ORIGINS: list = [
    "http://localhost:5173",  # Vite dev server
    "http://localhost:3000",  # React dev server
    "http://localhost:8000",  # Production
]

# Logging settings
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE: Optional[str] = os.getenv("LOG_FILE", "logs/app.log")

# OpenAI settings (for NLP report generation)
OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4")

# Feature flags
ENABLE_ML_ANALYSIS: bool = os.getenv("ENABLE_ML_ANALYSIS", "true").lower() == "true"
ENABLE_NLP_REPORTS: bool = os.getenv("ENABLE_NLP_REPORTS", "true").lower() == "true"

