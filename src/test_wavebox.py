import asyncio
import logging
import os
from pathlib import Path
from playwright.async_api import async_playwright

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_wavebox():
    """Test BrowserService with Wavebox using existing profile."""
    wavebox_path = "/Applications/Wavebox.app/Contents/MacOS/Wavebox"
    user_data_dir = str(Path.home() / "Library/Application Support/WaveboxApp")

    if not os.path.exists(wavebox_path):
        logger.error(f"Wavebox not found at {wavebox_path}")
        return

    if not os.path.exists(user_data_dir):
        logger.error(f"Wavebox profile not found at {user_data_dir}")
        return

    try:
        logger.info("Initializing Playwright...")
        async with async_playwright() as p:
            # Launch Wavebox with existing profile
            logger.info(f"Launching Wavebox with profile from {user_data_dir}...")
            context = await p.chromium.launch_persistent_context(
                user_data_dir=user_data_dir,
                executable_path=wavebox_path,
                headless=False,
                args=[
                    "--no-first-run",
                    "--no-default-browser-check",
                ]
            )

            try:
                # Create a new page
                logger.info("Creating new page...")
                page = await context.new_page()
                logger.info("New page created")

                # Test basic navigation
                logger.info("Navigating to example.com...")
                await page.goto("https://example.com", wait_until="networkidle")
                logger.info("Navigation completed")

                title = await page.title()
                logger.info(f"Page title: {title}")

                # Take a screenshot
                logger.info("Taking screenshot...")
                await page.screenshot(path="wavebox_test.png")
                logger.info("Screenshot saved as wavebox_test.png")

                logger.info("Test completed successfully!")

            finally:
                # Close the context (this will also close all pages)
                logger.info("Closing browser context...")
                await context.close()

    except Exception as e:
        logger.error(f"Test failed with error: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(test_wavebox())
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
    except Exception as e:
        logger.error(f"Test failed with error: {str(e)}")
        raise