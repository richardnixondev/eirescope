"""EireScope global configuration."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "eirescope", "data")

class Config:
    DEBUG = os.getenv("EIRESCOPE_DEBUG", "true").lower() == "true"
    SECRET_KEY = os.getenv("EIRESCOPE_SECRET_KEY", "eirescope-dev-key-change-in-production")
    DATABASE_URL = os.getenv("EIRESCOPE_DB_URL", f"sqlite:///{os.path.join(DATA_DIR, 'investigations.db')}")
    PLUGIN_DIR = os.path.join(BASE_DIR, "eirescope", "modules")
    CACHE_DIR = os.path.join(DATA_DIR, "cache")
    LOG_LEVEL = os.getenv("EIRESCOPE_LOG_LEVEL", "INFO")
    MAX_CONCURRENT_MODULES = int(os.getenv("EIRESCOPE_MAX_CONCURRENT", "5"))
    REQUEST_TIMEOUT = int(os.getenv("EIRESCOPE_REQUEST_TIMEOUT", "10"))
    MAX_RETRIES = int(os.getenv("EIRESCOPE_MAX_RETRIES", "3"))
    RATE_LIMIT_DELAY = float(os.getenv("EIRESCOPE_RATE_LIMIT", "0.5"))
    CACHE_TTL = int(os.getenv("EIRESCOPE_CACHE_TTL", "86400"))  # 24 hours

class ProductionConfig(Config):
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True
