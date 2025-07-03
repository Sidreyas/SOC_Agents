import logging
import os

LOG_FILE = "logs/investigation.log"

# Setup basic logging
def setup_logger():
    logger = logging.getLogger("AgentLogger")
    logger.setLevel(logging.INFO)
    
    # File handler
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.INFO)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger
