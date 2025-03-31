import asyncio
import time
from browser_actions.playwright_handlers import PlaywrightActionHandlers

async def test_playwright_approach():
    """Test the regular Playwright approach."""
    handler = PlaywrightActionHandlers()
    start_time = time.time()

    try:
        # Navigate to LinkedIn
        await handler.handle_playwright_navigate("https://linkedin.com")
        await asyncio.sleep(2)

        # Click Jobs using multiple possible selectors
        try:
            # Try nav link first
            await handler.handle_playwright_click('nav a[href*="jobs"]')
        except:
            try:
                # Try button
                await handler.handle_playwright_click('button:has-text("Jobs")')
            except:
                # Try any clickable element with Jobs text
                await handler.handle_playwright_click(':is(a,button,div)[role="button"]:has-text("Jobs")')

        await asyncio.sleep(2)

        end_time = time.time()
        return end_time - start_time
    finally:
        await handler.cleanup()

async def test_aria_approach():
    """Test the ARIA-based approach."""
    handler = PlaywrightActionHandlers()
    start_time = time.time()

    try:
        # Navigate to LinkedIn
        await handler.handle_playwright_navigate("https://linkedin.com")
        await asyncio.sleep(2)

        # Get ARIA snapshot and find Jobs link
        snapshot = await handler.handle_playwright_get_aria_snapshot()
        if snapshot["success"]:
            print("\nARIA Snapshot of interactive elements:")
            print(snapshot["text_representation"])

            # Find Jobs element
            jobs_element = None
            for el in snapshot["elements"]:
                if "Jobs" in str(el["name"]):
                    jobs_element = el
                    print(f"\nFound Jobs element: [{el['index']}] {el['role']}: {el['name']}")
                    print(f"Element metadata: {el['metadata']}")
                    break

            if jobs_element:
                await handler.handle_playwright_click_aria(jobs_element["index"])
            else:
                print("Could not find Jobs element using ARIA")
        else:
            print(f"Failed to get ARIA snapshot: {snapshot.get('error')}")

        await asyncio.sleep(2)
        end_time = time.time()
        return end_time - start_time
    finally:
        await handler.cleanup()

async def test_smart_approach():
    """Test the smart cascading approach."""
    handler = PlaywrightActionHandlers()
    start_time = time.time()

    try:
        # Navigate to LinkedIn
        await handler.handle_playwright_navigate("https://linkedin.com")
        await asyncio.sleep(2)

        # Try to click Jobs using smart click
        result = await handler.handle_smart_click("Jobs")
        print(f"\nSmart click result:")
        print(f"Success: {result['success']}")
        print(f"Strategy used: {result.get('strategy', 'none')}")
        print(f"Time taken: {result.get('time_taken', 0):.2f}s")

        if result.get('element'):
            print("Element found via ARIA:")
            print(f"Role: {result['element']['role']}")
            print(f"Name: {result['element']['name']}")
            print(f"Metadata: {result['element']['metadata']}")
        elif result.get('coordinates'):
            print("Element found via VNC:")
            print(f"Coordinates: {result['coordinates']}")
        elif result.get('selector'):
            print("Element found via Playwright:")
            print(f"Selector: {result['selector']}")

        await asyncio.sleep(2)

        # Try to type in the search box
        search_result = await handler.handle_smart_type(
            text="Python Developer",
            target="Search jobs"
        )
        print(f"\nSmart type result:")
        print(f"Success: {search_result['success']}")
        print(f"Strategy used: {search_result.get('strategy', 'none')}")
        print(f"Time taken: {search_result.get('time_taken', 0):.2f}s")

        end_time = time.time()
        return end_time - start_time
    finally:
        await handler.cleanup()

async def main():
    print("\nTesting regular Playwright approach...")
    playwright_time = await test_playwright_approach()
    print(f"Playwright approach took: {playwright_time:.2f} seconds")
    print("Context size for Playwright DOM: ~500KB-2MB")

    print("\nTesting ARIA approach...")
    aria_time = await test_aria_approach()
    print(f"ARIA approach took: {aria_time:.2f} seconds")
    print("Context size for ARIA: ~10-20KB")

    print("\nTesting smart cascading approach...")
    smart_time = await test_smart_approach()
    print(f"\nTotal time taken: {smart_time:.2f} seconds")
    print("\nStrategy cascade order:")
    print("1. ARIA (default) - Context: ~10-20KB")
    print("2. VNC/MacOS (secondary) - Context: ~100KB per screenshot")
    print("3. Playwright (fallback) - Context: ~500KB-2MB")

    print("\nComparison Summary:")
    print(f"Playwright Time: {playwright_time:.2f}s - Context: ~500KB-2MB")
    print(f"ARIA Time: {aria_time:.2f}s - Context: ~10-20KB")

if __name__ == "__main__":
    asyncio.run(main())