import os
import sys
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

# Add src to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock MCP modules
sys.modules['mcp'] = MagicMock()
sys.modules['mcp.server'] = MagicMock()
sys.modules['mcp.server.models'] = MagicMock()
sys.modules['mcp.types'] = MagicMock()
sys.modules['mcp.server.stdio'] = MagicMock()

# Import after mocking
from src.mcp_remote_macos_use.server import MCPServer, MacOSActionHandlers
from src.browser_actions import PlaywrightActionHandlers

@pytest.fixture
def mock_env_vars():
    """Set up environment variables for testing."""
    with patch.dict('os.environ', {
        'MACOS_HOST': 'test-host',
        'MACOS_PORT': '5900',
        'MACOS_USERNAME': 'test-user',
        'MACOS_PASSWORD': 'test-password',
        'VNC_ENCRYPTION': 'prefer_on'
    }):
        yield

@pytest.fixture
def mock_vnc_client():
    """Mock VNC client."""
    with patch('src.mcp_remote_macos_use.server.VNCClient') as mock:
        mock.return_value = AsyncMock()
        yield mock

@pytest.fixture
def mock_playwright():
    """Mock Playwright browser."""
    with patch('src.browser_actions.playwright_handlers.async_playwright') as mock:
        browser_mock = AsyncMock()
        context_mock = AsyncMock()
        page_mock = AsyncMock()

        mock.return_value = AsyncMock()
        mock.return_value.__aenter__.return_value = browser_mock
        browser_mock.chromium.launch = AsyncMock(return_value=browser_mock)
        browser_mock.new_context = AsyncMock(return_value=context_mock)
        context_mock.new_page = AsyncMock(return_value=page_mock)

        yield mock

@pytest.mark.asyncio
async def test_tool_registration(mock_env_vars, mock_vnc_client, mock_playwright):
    """Test that all tools are properly registered."""
    # Create MCPServer instance
    server = MCPServer()

    # Initialize server
    await server.initialize()

    try:
        # Get tool definitions
        tools = server.tool_definitions

        # Verify VNC tools are registered
        vnc_tools = [
            "remote_macos_get_screen",
            "remote_macos_mouse_scroll",
            "remote_macos_mouse_click",
            "remote_macos_mouse_double_click",
            "remote_macos_mouse_move",
            "remote_macos_send_keys"
        ]
        for tool in vnc_tools:
            assert tool in tools, f"VNC tool {tool} not found in registered tools"
            assert "description" in tools[tool], f"VNC tool {tool} missing description"
            assert "parameters" in tools[tool], f"VNC tool {tool} missing parameters"

        # Verify Playwright tools are registered
        playwright_tools = [
            "browser_playwright_navigate",
            "browser_playwright_screenshot",
            "browser_playwright_click",
            "browser_playwright_fill",
            "browser_playwright_evaluate",
            "browser_playwright_get_visible_text",
            "browser_playwright_get_visible_html"
        ]
        for tool in playwright_tools:
            assert tool in tools, f"Playwright tool {tool} not found in registered tools"
            assert "description" in tools[tool], f"Playwright tool {tool} missing description"
            assert "parameters" in tools[tool], f"Playwright tool {tool} missing parameters"

        # Verify ARIA tools are registered
        aria_tools = [
            "browser_playwright_get_aria_snapshot",
            "browser_playwright_click_aria",
            "browser_smart_click",
            "browser_smart_type"
        ]
        for tool in aria_tools:
            assert tool in tools, f"ARIA tool {tool} not found in registered tools"
            assert "description" in tools[tool], f"ARIA tool {tool} missing description"
            assert "parameters" in tools[tool], f"ARIA tool {tool} missing parameters"

        # Print summary
        print(f"\nTotal tools registered: {len(tools)}")
        print(f"VNC tools: {len(vnc_tools)}")
        print(f"Playwright tools: {len(playwright_tools)}")
        print(f"ARIA tools: {len(aria_tools)}")

    finally:
        # Cleanup
        await server.cleanup()

@pytest.mark.asyncio
async def test_tool_handler_resolution(mock_env_vars, mock_vnc_client, mock_playwright):
    """Test that tool handlers are properly resolved."""
    server = MCPServer()
    await server.initialize()

    try:
        # Test VNC tool handler
        result = await server.handle_request("remote_macos_get_screen", {})
        assert isinstance(result, dict)
        assert "success" in result

        # Test Playwright tool handler
        result = await server.handle_request("browser_playwright_get_visible_text", {})
        assert isinstance(result, dict)
        assert "success" in result

        # Test ARIA tool handler
        result = await server.handle_request("browser_playwright_get_aria_snapshot", {})
        assert isinstance(result, dict)
        assert "success" in result

        # Test smart tool handler
        result = await server.handle_request("browser_smart_click", {"target": "test"})
        assert isinstance(result, dict)
        assert "success" in result

    finally:
        await server.cleanup()

@pytest.mark.asyncio
async def test_invalid_tool_handling(mock_env_vars, mock_vnc_client, mock_playwright):
    """Test handling of invalid tool requests."""
    server = MCPServer()
    await server.initialize()

    try:
        # Test non-existent tool
        result = await server.handle_request("non_existent_tool", {})
        assert isinstance(result, dict)
        assert not result.get("success", True)
        assert "error" in result

        # Test invalid browser tool
        result = await server.handle_request("browser_invalid_tool", {})
        assert isinstance(result, dict)
        assert not result.get("success", True)
        assert "error" in result

    finally:
        await server.cleanup()

if __name__ == "__main__":
    pytest.main([__file__, "-v"])