from . import server
from .tools import fscan_tool  # import tools to trigger registry
from . import logger
import asyncio
import logging

def main():
    """Main entry point for the package."""
    logger.setup_logging()
    proj_logger = logging.getLogger(__name__)
    proj_logger.info("Starting MCP server")
    asyncio.run(server.main())

# Optionally expose other important items at package level
__all__ = ['main', 'server']