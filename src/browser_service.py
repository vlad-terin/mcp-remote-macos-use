import asyncio
from typing import Optional, Dict, Any, List
from playwright.async_api import async_playwright, Browser, Page, ElementHandle
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BrowserService:
    def __init__(self, browser_type: str = "chromium", headless: bool = True,
                 executable_path: Optional[str] = None, browser_args: Optional[List[str]] = None):
        """
        Initialize the browser service.
        Args:
            browser_type: Type of browser to use ("chromium", "firefox", or "webkit")
            headless: Whether to run browser in headless mode
            executable_path: Path to browser executable (e.g., Wavebox)
            browser_args: Additional browser arguments
        """
        self.browser_type = browser_type
        self.headless = headless
        self.executable_path = executable_path
        self.browser_args = browser_args or []
        self.playwright = None
        self.browser = None
        self.page = None

    async def start(self, user_data_dir: Optional[str] = None) -> None:
        """Start the browser service with optional user data directory."""
        try:
            self.playwright = await async_playwright().start()
            browser_instance = getattr(self.playwright, self.browser_type)

            launch_args = {
                "headless": self.headless
            }

            if self.executable_path:
                launch_args["executable_path"] = self.executable_path

            if self.browser_args:
                launch_args["args"] = self.browser_args

            if user_data_dir:
                launch_args["user_data_dir"] = user_data_dir

            self.browser = await browser_instance.launch(**launch_args)
            self.page = await self.browser.new_page()
            logger.info(f"Started {self.browser_type} browser service")
            if self.executable_path:
                logger.info(f"Using custom executable: {self.executable_path}")
        except Exception as e:
            logger.error(f"Failed to start browser service: {e}")
            await self.cleanup()
            raise

    async def cleanup(self) -> None:
        """Clean up browser resources."""
        try:
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("Browser service cleaned up")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    async def navigate(self, url: str, wait_until: str = "load") -> None:
        """Navigate to a URL and wait for the specified event."""
        try:
            await self.page.goto(url, wait_until=wait_until)
            logger.info(f"Navigated to {url}")
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            raise

    async def get_element(self, selector: str) -> Optional[ElementHandle]:
        """Get an element using a CSS selector."""
        try:
            element = await self.page.wait_for_selector(selector)
            return element
        except Exception as e:
            logger.error(f"Failed to find element with selector {selector}: {e}")
            return None

    async def click(self, selector: str) -> None:
        """Click an element using a CSS selector."""
        try:
            await self.page.click(selector)
            logger.info(f"Clicked element with selector: {selector}")
        except Exception as e:
            logger.error(f"Click failed: {e}")
            raise

    async def type_text(self, selector: str, text: str) -> None:
        """Type text into an element."""
        try:
            await self.page.fill(selector, text)
            logger.info(f"Typed text into element with selector: {selector}")
        except Exception as e:
            logger.error(f"Type text failed: {e}")
            raise

    async def get_text(self, selector: str) -> Optional[str]:
        """Get text content of an element."""
        try:
            element = await self.get_element(selector)
            if element:
                return await element.text_content()
            return None
        except Exception as e:
            logger.error(f"Failed to get text: {e}")
            return None

    async def evaluate(self, script: str) -> Any:
        """Evaluate JavaScript in the page context."""
        try:
            return await self.page.evaluate(script)
        except Exception as e:
            logger.error(f"Script evaluation failed: {e}")
            raise

    async def screenshot(self, path: Optional[str] = None, full_page: bool = False) -> Optional[bytes]:
        """Take a screenshot of the page."""
        try:
            return await self.page.screenshot(path=path, full_page=full_page)
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            raise

    async def get_cookies(self) -> List[Dict[str, Any]]:
        """Get all cookies for the current page."""
        try:
            return await self.page.context.cookies()
        except Exception as e:
            logger.error(f"Failed to get cookies: {e}")
            return []

    async def set_cookies(self, cookies: List[Dict[str, Any]]) -> None:
        """Set cookies for the current page."""
        try:
            await self.page.context.add_cookies(cookies)
            logger.info("Cookies set successfully")
        except Exception as e:
            logger.error(f"Failed to set cookies: {e}")
            raise

    async def wait_for_navigation(self, timeout: int = 30000) -> None:
        """Wait for page navigation to complete."""
        try:
            await self.page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception as e:
            logger.error(f"Navigation wait failed: {e}")
            raise

# Simple test function
async def test_browser_service():
    service = BrowserService()
    try:
        print("Initializing browser...")
        success = await service.start()
        if not success:
            print("Failed to initialize browser")
            return

        print("Navigating to example.com...")
        await service.navigate("https://example.com")

        print("Getting page title...")
        title = await service.page.title()
        print(f"Page title: {title}")

        print("Taking screenshot...")
        await service.screenshot(path="test_screenshot.png")

        print("Waiting 3 seconds...")
        await asyncio.sleep(3)

    finally:
        print("Cleaning up...")
        await service.cleanup()

if __name__ == "__main__":
    asyncio.run(test_browser_service())