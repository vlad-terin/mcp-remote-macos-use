import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto('https://example.com')
        title = await page.title()
        print(f"Page title: {title}")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())