import asyncio
import logging
from browser_service import BrowserService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_browser_service():
    """Test various capabilities of the BrowserService class."""
    service = BrowserService(headless=False)  # Set headless=False to see the browser in action

    try:
        # Start the browser
        await service.start()

        # Test navigation and basic page interaction
        await service.navigate("https://example.com")
        title = await service.page.title()
        logger.info(f"Page title: {title}")

        # Test JavaScript evaluation
        viewport_height = await service.evaluate("window.innerHeight")
        logger.info(f"Viewport height: {viewport_height}")

        # Test element interaction
        heading_text = await service.get_text("h1")
        logger.info(f"Main heading: {heading_text}")

        # Test navigation to a more interactive page
        await service.navigate("https://www.google.com")

        # Test typing into search box
        await service.type_text('input[name="q"]', "Playwright Python")

        # Take a screenshot
        await service.screenshot(path="google_search.png")

        # Test cookie handling
        cookies = await service.get_cookies()
        logger.info(f"Number of cookies: {len(cookies)}")

        # Test multiple page handling
        new_page = await service.browser.new_page()
        await new_page.goto("https://github.com")
        await new_page.screenshot(path="github.png")
        await new_page.close()

        logger.info("All tests completed successfully!")

    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise
    finally:
        await service.cleanup()

if __name__ == "__main__":
    asyncio.run(test_browser_service())