import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from osint_framework.core.config import settings

def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
        
    level_name = settings.logging.level.upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)
    
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Console Handler
    if settings.logging.console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File Handler
    if settings.logging.file:
        log_path = Path(settings.logging.file)
        if log_path.parent and str(log_path.parent) not in {"", "."}:
            log_path.parent.mkdir(parents=True, exist_ok=True)

        if settings.logging.rotate:
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=max(0, int(settings.logging.max_bytes or 0)),
                backupCount=max(0, int(settings.logging.backup_count or 0)),
                encoding="utf-8",
            )
        else:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger

logger = setup_logger("osint_framework")
