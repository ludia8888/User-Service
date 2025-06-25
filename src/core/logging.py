"""
Logging configuration
"""
import logging
import sys
from pythonjsonlogger import jsonlogger

from .config import settings


def setup_logging():
    """Setup structured logging"""
    # Remove default handlers
    logging.root.handlers = []
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    
    # Set formatter based on config
    if settings.LOG_FORMAT == "json":
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    handler.setFormatter(formatter)
    
    # Configure root logger
    logging.root.addHandler(handler)
    logging.root.setLevel(getattr(logging, settings.LOG_LEVEL))
    
    # Reduce noise from libraries
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)