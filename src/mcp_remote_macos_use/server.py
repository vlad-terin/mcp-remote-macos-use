import logging
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv
import base64
import socket
import time
import io
from PIL import Image
import asyncio
import pyDes
import json
import os
from base64 import b64encode
from datetime import datetime
import sys

# Import MCP server libraries
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Import VNC client functionality from the src directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vnc_client import VNCClient, capture_vnc_screen

# Import action handlers from the src directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from action_handlers import (
    handle_remote_macos_get_screen,
    handle_remote_macos_mouse_scroll,
    handle_remote_macos_send_keys,
    handle_remote_macos_mouse_move,
    handle_remote_macos_mouse_click,
    handle_remote_macos_mouse_double_click
)

# Import browser actions from the src directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from browser_actions import PlaywrightActionHandlers

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('mcp_remote_macos_use')
logger.setLevel(logging.DEBUG)

# Load environment variables for VNC connection
MACOS_HOST = os.environ.get('MACOS_HOST', '')
MACOS_PORT = int(os.environ.get('MACOS_PORT', '5900'))
MACOS_USERNAME = os.environ.get('MACOS_USERNAME', '')
MACOS_PASSWORD = os.environ.get('MACOS_PASSWORD', '')
VNC_ENCRYPTION = os.environ.get('VNC_ENCRYPTION', 'prefer_on')

# Log environment variable status (without exposing actual values)
logger.info(f"MACOS_HOST from environment: {'Set' if MACOS_HOST else 'Not set'}")
logger.info(f"MACOS_PORT from environment: {MACOS_PORT}")
logger.info(f"MACOS_USERNAME from environment: {'Set' if MACOS_USERNAME else 'Not set'}")
logger.info(f"MACOS_PASSWORD from environment: {'Set' if MACOS_PASSWORD else 'Not set (Required)'}")
logger.info(f"VNC_ENCRYPTION from environment: {VNC_ENCRYPTION}")

# Validate required environment variables
if not MACOS_HOST:
    logger.error("MACOS_HOST environment variable is required but not set")
    raise ValueError("MACOS_HOST environment variable is required but not set")

if not MACOS_PASSWORD:
    logger.error("MACOS_PASSWORD environment variable is required but not set")
    raise ValueError("MACOS_PASSWORD environment variable is required but not set")

# Initialize global MCP server
mcp_server = None

class MacOSActionHandlers:
    """Handles VNC-based actions for MacOS remote control."""

    def __init__(self):
        self.vnc_client = None

    async def initialize(self):
        """Initialize VNC client."""
        if not self.vnc_client:
            self.vnc_client = VNCClient(
                host=MACOS_HOST,
                port=MACOS_PORT,
                username=MACOS_USERNAME,
                password=MACOS_PASSWORD,
                encryption=VNC_ENCRYPTION
            )

    async def cleanup(self):
        """Clean up VNC client."""
        if self.vnc_client:
            await self.vnc_client.close()
            self.vnc_client = None

    @property
    def tool_definitions(self) -> Dict[str, Dict[str, Any]]:
        """Get tool definitions for MacOS actions."""
        return {
            "remote_macos_get_screen": {
                "description": "Get a screenshot of the remote desktop",
                "parameters": {}
            },
            "remote_macos_mouse_scroll": {
                "description": "Perform a mouse scroll",
                "parameters": {
                    "x": {"type": "integer", "description": "X coordinate"},
                    "y": {"type": "integer", "description": "Y coordinate"},
                    "direction": {"type": "string", "enum": ["up", "down"], "default": "down"}
                }
            },
            "remote_macos_mouse_click": {
                "description": "Perform a mouse click",
                "parameters": {
                    "x": {"type": "integer", "description": "X coordinate"},
                    "y": {"type": "integer", "description": "Y coordinate"},
                    "button": {"type": "integer", "default": 1}
                }
            },
            "remote_macos_mouse_double_click": {
                "description": "Perform a mouse double-click",
                "parameters": {
                    "x": {"type": "integer", "description": "X coordinate"},
                    "y": {"type": "integer", "description": "Y coordinate"},
                    "button": {"type": "integer", "default": 1}
                }
            },
            "remote_macos_mouse_move": {
                "description": "Move the mouse cursor",
                "parameters": {
                    "x": {"type": "integer", "description": "X coordinate"},
                    "y": {"type": "integer", "description": "Y coordinate"}
                }
            },
            "remote_macos_send_keys": {
                "description": "Send keyboard input",
                "parameters": {
                    "text": {"type": "string", "description": "Text to type"},
                    "special_key": {"type": "string", "description": "Special key to send"},
                    "key_combination": {"type": "string", "description": "Key combination to send"}
                }
            }
        }

    async def handle_remote_macos_get_screen(self, **kwargs) -> Dict[str, Any]:
        """Get a screenshot of the remote desktop."""
        await self.initialize()
        try:
            screenshot = await capture_vnc_screen(self.vnc_client)
            return {"success": True, "screenshot": screenshot}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def handle_remote_macos_mouse_scroll(self, x: int, y: int, direction: str = "down", **kwargs) -> Dict[str, Any]:
        """Perform a mouse scroll."""
        await self.initialize()
        try:
            await self.vnc_client.mouse_scroll(x, y, direction)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def handle_remote_macos_mouse_click(self, x: int, y: int, button: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform a mouse click."""
        await self.initialize()
        try:
            await self.vnc_client.mouse_click(x, y, button)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def handle_remote_macos_mouse_double_click(self, x: int, y: int, button: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform a mouse double-click."""
        await self.initialize()
        try:
            await self.vnc_client.mouse_double_click(x, y, button)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def handle_remote_macos_mouse_move(self, x: int, y: int, **kwargs) -> Dict[str, Any]:
        """Move the mouse cursor."""
        await self.initialize()
        try:
            await self.vnc_client.mouse_move(x, y)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def handle_remote_macos_send_keys(self, text: Optional[str] = None,
                                          special_key: Optional[str] = None,
                                          key_combination: Optional[str] = None,
                                          **kwargs) -> Dict[str, Any]:
        """Send keyboard input."""
        await self.initialize()
        try:
            if text:
                await self.vnc_client.send_keys(text)
            elif special_key:
                await self.vnc_client.send_special_key(special_key)
            elif key_combination:
                await self.vnc_client.send_key_combination(key_combination)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

class MCPServer:
    def __init__(self):
        self.macos_handlers = MacOSActionHandlers()
        self.browser_handlers = PlaywrightActionHandlers()
        self._initialized = False
        self._tool_definitions = None

    async def initialize(self):
        """Initialize all handlers."""
        if self._initialized:
            return

        # Initialize MacOS handlers if needed
        if hasattr(self.macos_handlers, 'initialize'):
            await self.macos_handlers.initialize()

        # Initialize browser handlers
        await self.browser_handlers.ensure_browser(headless=True)

        # Cache tool definitions
        self._tool_definitions = self._get_tool_definitions()
        self._initialized = True

    async def cleanup(self):
        """Cleanup all handlers."""
        # Cleanup MacOS handlers
        if hasattr(self.macos_handlers, 'cleanup'):
            await self.macos_handlers.cleanup()

        # Cleanup browser handlers
        await self.browser_handlers.cleanup()
        self._initialized = False
        self._tool_definitions = None

    def _get_tool_definitions(self) -> Dict[str, Dict[str, Any]]:
        """Get all tool definitions."""
        tools = {}

        # Add MacOS tools
        if hasattr(self.macos_handlers, 'tool_definitions'):
            tools.update(self.macos_handlers.tool_definitions)

        # Add browser tools with proper prefixes
        if hasattr(self.browser_handlers, 'tool_definitions'):
            browser_tools = self.browser_handlers.tool_definitions
            for name, tool in browser_tools.items():
                tools[f"browser_{name}"] = tool

        return tools

    @property
    def tool_definitions(self) -> Dict[str, Dict[str, Any]]:
        """Get cached tool definitions."""
        if not self._tool_definitions:
            self._tool_definitions = self._get_tool_definitions()
        return self._tool_definitions

    async def handle_request(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a tool request."""
        if not self._initialized:
            await self.initialize()

        try:
            # Handle MacOS tools
            if tool_name in self.macos_handlers.tool_definitions:
                handler = getattr(self.macos_handlers, f"handle_{tool_name}")
                return await handler(**params)

            # Handle browser tools
            if tool_name.startswith("browser_"):
                browser_tool = tool_name[len("browser_"):]
                if hasattr(self.browser_handlers, f"handle_{browser_tool}"):
                    handler = getattr(self.browser_handlers, f"handle_{browser_tool}")
                    return await handler(**params)

            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        except Exception as e:
            logger.error(f"Error handling tool request: {str(e)}", exc_info=True)
            return {"success": False, "error": str(e)}

async def main():
    """Run the Remote MacOS MCP server."""
    logger.info("Remote MacOS computer use server starting")

    # Initialize global MCP server
    global mcp_server
    mcp_server = MCPServer()
    await mcp_server.initialize()

    server = Server("remote-macos-client")

    @server.list_resources()
    async def handle_list_resources() -> list[types.Resource]:
        return []

    @server.read_resource()
    async def handle_read_resource(uri: types.AnyUrl) -> str:
        return ""

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        """List available tools"""
        tools = []

        # Get all tools from MCPServer
        for name, tool_def in mcp_server.tool_definitions.items():
            tools.append(types.Tool(
                name=name,
                description=tool_def.get('description', ''),
                inputSchema=tool_def.get('parameters', {})
            ))

        return tools

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Handle tool execution requests"""
        try:
            if not arguments:
                arguments = {}

            # Handle all tools through MCPServer
            result = await mcp_server.handle_request(name, arguments)

            # Convert result to appropriate response type
            if isinstance(result, dict):
                if result.get('success', False):
                    # Handle special cases
                    if 'screenshot' in result:
                        # Return screenshot as image content
                        return [types.ImageContent(type="image", data=result['screenshot'])]
                    elif 'html' in result:
                        # Return HTML as text content
                        return [types.TextContent(type="text", text=result['html'])]
                    else:
                        # Return general success result
                        return [types.TextContent(type="text", text=str(result))]
                else:
                    # Return error message
                    return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]
            else:
                # Return raw result
                return [types.TextContent(type="text", text=str(result))]

        except Exception as e:
            logger.error(f"Error in handle_call_tool: {str(e)}", exc_info=True)
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            logger.info("Server running with stdio transport")
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="vnc-client",
                    server_version="0.1.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
    finally:
        await mcp_server.cleanup()

if __name__ == "__main__":
    # Load environment variables from .env file if it exists
    load_dotenv()

    try:
        # Run the server
        asyncio.run(main())
    except ValueError as e:
        logger.error(f"Initialization failed: {str(e)}")
        print(f"ERROR: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        print(f"ERROR: Unexpected error occurred: {str(e)}")
        sys.exit(1)