import logging
import os


def get_logger(name: str = "todo_mcp_server") -> logging.Logger:
    logger = logging.getLogger(name)
    level = os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(getattr(logging, level))

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
