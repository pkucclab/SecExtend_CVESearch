from typing import Any, Dict, List
import logging

logger = logging.getLogger(__name__)

class ToolRegistry:
    """manage all tools in mcp, new tools need to be registered first """
    
    def __init__(self):
        self._tools: Dict[str, object] = {}

    def register(self, tool) -> None:
        """register a tool"""
        logger.info(f"Registering tool: {tool.name}")
        if tool.name in self._tools:
            raise ValueError(f"Tool {tool.name} already registered")
        
        self._tools[tool.name] = tool

    def get_tool(self, name: str):
        """instantiate a tool"""
        logger.debug(f"Getting tool: {name}")
        
        if name not in self._tools:
            logger.error(f"Tool {name} not found")
            raise ValueError(f"Tool {name} not found")
            
        logger.debug(f"Tool {name} found")
        return self._tools[name]

    def list_tools(self) -> List[Dict[str, Any]]:
        """list all the tools"""
        logger.debug("Listing all tools")
        tools = [
            {
                'name': tool.name,
                'description': tool.description,
                'input_schema': tool.input_schema
            }
            for tool in self._tools.values()
        ]
        logger.debug(f"Found {len(tools)} tools")
        return tools

tool_registry = ToolRegistry()