import logging
import sys

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
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File Handler
    if settings.logging.file:
        file_handler = logging.FileHandler(settings.logging.file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger

logger = setup_logger("osint_framework")
