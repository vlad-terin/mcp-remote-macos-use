import asyncio
import logging
import os
from typing import Any, Dict, Optional, List
from playwright.async_api import async_playwright, Browser, Page, Response
import base64
from pathlib import Path
import json
import time

logger = logging.getLogger(__name__)

class PlaywrightActionHandlers:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self._browser_lock = asyncio.Lock()
        self._response_waiters = {}
        self._codegen_sessions = {}
        self._interactive_elements = []
        self._last_snapshot = None

    async def ensure_browser(self, browser_type: str = "chromium", headless: bool = False,
                           width: int = 1280, height: int = 720):
        """Ensure browser is initialized and running."""
        if not self.browser:
            async with self._browser_lock:
                if not self.browser:  # Double check after acquiring lock
                    self.playwright = await async_playwright().start()
                    browser_context = getattr(self.playwright, browser_type)
                    self.browser = await browser_context.launch(headless=headless)
                    self.page = await self.browser.new_page()
                    await self.page.set_viewport_size({"width": width, "height": height})
                    logger.info(f"Browser initialized: {browser_type}")

    async def cleanup(self):
        """Clean up browser resources."""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self.browser = None
        self.playwright = None
        self.page = None
        self._response_waiters.clear()
        self._codegen_sessions.clear()

    # Browser Navigation Tools
    async def handle_playwright_navigate(self, url: str, browser_type: str = "chromium",
                                      width: int = 1280, height: int = 720,
                                      timeout: int = 30000, wait_until: str = "load",
                                      headless: bool = False) -> Dict[str, Any]:
        """Navigate to a URL."""
        await self.ensure_browser(browser_type, headless, width, height)
        try:
            response = await self.page.goto(url, timeout=timeout, wait_until=wait_until)
            return {
                "success": True,
                "title": await self.page.title(),
                "status": response.status if response else None
            }
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            return {"success": False, "error": str(e)}

    # Screenshot Tools
    async def handle_playwright_screenshot(self, name: str, selector: Optional[str] = None,
                                        width: int = 800, height: int = 600,
                                        store_base64: bool = True, full_page: bool = False,
                                        save_png: bool = False,
                                        downloads_dir: Optional[str] = None) -> Dict[str, Any]:
        """Take a screenshot of the page or element."""
        await self.ensure_browser()
        try:
            if selector:
                element = await self.page.wait_for_selector(selector)
                screenshot = await element.screenshot()
            else:
                screenshot = await self.page.screenshot(full_page=full_page)

            result = {"success": True}

            if store_base64:
                result["screenshot_base64"] = base64.b64encode(screenshot).decode()

            if save_png:
                downloads_path = downloads_dir or os.path.expanduser("~/Downloads")
                file_path = os.path.join(downloads_path, f"{name}.png")
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "wb") as f:
                    f.write(screenshot)
                result["file_path"] = file_path

            return result
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return {"success": False, "error": str(e)}

    # Element Interaction Tools
    async def handle_playwright_click(self, selector: str) -> Dict[str, Any]:
        """Click an element on the page."""
        await self.ensure_browser()
        try:
            await self.page.click(selector)
            return {"success": True}
        except Exception as e:
            logger.error(f"Click failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_iframe_click(self, iframe_selector: str, selector: str) -> Dict[str, Any]:
        """Click an element inside an iframe."""
        await self.ensure_browser()
        try:
            iframe = await self.page.frame_locator(iframe_selector)
            await iframe.locator(selector).click()
            return {"success": True}
        except Exception as e:
            logger.error(f"IFrame click failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_fill(self, selector: str, value: str) -> Dict[str, Any]:
        """Fill an input field."""
        await self.ensure_browser()
        try:
            await self.page.fill(selector, value)
            return {"success": True}
        except Exception as e:
            logger.error(f"Fill failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_select(self, selector: str, value: str) -> Dict[str, Any]:
        """Select an option from a select element."""
        await self.ensure_browser()
        try:
            await self.page.select_option(selector, value)
            return {"success": True}
        except Exception as e:
            logger.error(f"Select failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_hover(self, selector: str) -> Dict[str, Any]:
        """Hover over an element."""
        await self.ensure_browser()
        try:
            await self.page.hover(selector)
            return {"success": True}
        except Exception as e:
            logger.error(f"Hover failed: {e}")
            return {"success": False, "error": str(e)}

    # JavaScript Evaluation Tools
    async def handle_playwright_evaluate(self, script: str) -> Dict[str, Any]:
        """Evaluate JavaScript in the page context."""
        await self.ensure_browser()
        try:
            result = await self.page.evaluate(script)
            return {"success": True, "result": result}
        except Exception as e:
            logger.error(f"Script evaluation failed: {e}")
            return {"success": False, "error": str(e)}

    # Console and Network Tools
    async def handle_playwright_console_logs(self, type: str = "all", search: Optional[str] = None,
                                          limit: Optional[int] = None, clear: bool = False) -> Dict[str, Any]:
        """Get console logs with filtering options."""
        await self.ensure_browser()
        try:
            logs = []
            def handle_console(msg):
                if type == "all" or msg.type == type:
                    if not search or search in msg.text:
                        logs.append({"type": msg.type, "text": msg.text})

            self.page.on("console", handle_console)
            if clear:
                await self.page.evaluate("console.clear()")

            if limit:
                logs = logs[:limit]

            return {"success": True, "logs": logs}
        except Exception as e:
            logger.error(f"Console logs failed: {e}")
            return {"success": False, "error": str(e)}

    # HTTP Request Tools
    async def handle_playwright_get(self, url: str) -> Dict[str, Any]:
        """Perform GET request."""
        await self.ensure_browser()
        try:
            response = await self.page.request.get(url)
            return {
                "success": True,
                "status": response.status,
                "body": await response.text()
            }
        except Exception as e:
            logger.error(f"GET request failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_post(self, url: str, value: str,
                                  token: Optional[str] = None,
                                  headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Perform POST request."""
        await self.ensure_browser()
        try:
            request_headers = headers or {}
            if token:
                request_headers["Authorization"] = f"Bearer {token}"

            response = await self.page.request.post(url, data=value, headers=request_headers)
            return {
                "success": True,
                "status": response.status,
                "body": await response.text()
            }
        except Exception as e:
            logger.error(f"POST request failed: {e}")
            return {"success": False, "error": str(e)}

    # Response Assertion Tools
    async def handle_playwright_expect_response(self, id: str, url: str) -> Dict[str, Any]:
        """Start waiting for a response matching the URL pattern."""
        try:
            self._response_waiters[id] = {"url": url, "future": asyncio.Future()}
            return {"success": True, "id": id}
        except Exception as e:
            logger.error(f"Expect response failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_assert_response(self, id: str, value: Optional[str] = None) -> Dict[str, Any]:
        """Assert a response matches expected criteria."""
        try:
            if id not in self._response_waiters:
                return {"success": False, "error": f"No response waiter found for id: {id}"}

            waiter = self._response_waiters[id]
            response = await waiter["future"]

            if value:
                response_text = await response.text()
                if value not in response_text:
                    return {"success": False, "error": "Response body did not match expected value"}

            return {"success": True, "status": response.status}
        except Exception as e:
            logger.error(f"Assert response failed: {e}")
            return {"success": False, "error": str(e)}

    # Browser Control Tools
    async def handle_playwright_custom_user_agent(self, user_agent: str) -> Dict[str, Any]:
        """Set custom user agent."""
        await self.ensure_browser()
        try:
            await self.page.set_extra_http_headers({"User-Agent": user_agent})
            return {"success": True}
        except Exception as e:
            logger.error(f"Set user agent failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_get_visible_text(self) -> Dict[str, Any]:
        """Get visible text content."""
        await self.ensure_browser()
        try:
            text = await self.page.text_content("body")
            return {"success": True, "text": text}
        except Exception as e:
            logger.error(f"Get visible text failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_get_visible_html(self) -> Dict[str, Any]:
        """Get page HTML content."""
        await self.ensure_browser()
        try:
            html = await self.page.content()
            return {"success": True, "html": html}
        except Exception as e:
            logger.error(f"Get visible HTML failed: {e}")
            return {"success": False, "error": str(e)}

    # Navigation History Tools
    async def handle_playwright_go_back(self) -> Dict[str, Any]:
        """Navigate back in history."""
        await self.ensure_browser()
        try:
            await self.page.go_back()
            return {"success": True}
        except Exception as e:
            logger.error(f"Go back failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_go_forward(self) -> Dict[str, Any]:
        """Navigate forward in history."""
        await self.ensure_browser()
        try:
            await self.page.go_forward()
            return {"success": True}
        except Exception as e:
            logger.error(f"Go forward failed: {e}")
            return {"success": False, "error": str(e)}

    # Advanced Interaction Tools
    async def handle_playwright_drag(self, source_selector: str, target_selector: str) -> Dict[str, Any]:
        """Drag and drop elements."""
        await self.ensure_browser()
        try:
            source = await self.page.wait_for_selector(source_selector)
            target = await self.page.wait_for_selector(target_selector)

            await source.drag_to(target)
            return {"success": True}
        except Exception as e:
            logger.error(f"Drag failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_press_key(self, key: str, selector: Optional[str] = None) -> Dict[str, Any]:
        """Press a keyboard key."""
        await self.ensure_browser()
        try:
            if selector:
                await self.page.focus(selector)
            await self.page.keyboard.press(key)
            return {"success": True}
        except Exception as e:
            logger.error(f"Key press failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_save_as_pdf(self, output_path: str, filename: str = "page.pdf",
                                         format: str = "A4", print_background: bool = True,
                                         margin: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Save page as PDF."""
        await self.ensure_browser()
        try:
            pdf_path = os.path.join(output_path, filename)
            os.makedirs(output_path, exist_ok=True)

            options = {
                "path": pdf_path,
                "format": format,
                "printBackground": print_background
            }
            if margin:
                options["margin"] = margin

            await self.page.pdf(options)
            return {"success": True, "path": pdf_path}
        except Exception as e:
            logger.error(f"PDF save failed: {e}")
            return {"success": False, "error": str(e)}

    async def _inject_aria_helpers(self):
        """Inject helper functions for ARIA interaction."""
        return await self.page.evaluate("""() => {
            function findInteractiveElements() {
                // Native interactive HTML elements that are inherently focusable/clickable
                const INTERACTIVE_ELEMENTS = [
                    'a[href]',
                    'button',
                    'input:not([type="hidden"])',
                    'select',
                    'textarea',
                    'summary',
                    'video[controls]',
                    'audio[controls]',
                    '[tabindex]:not([tabindex="-1"])',
                    '[contenteditable="true"]'
                ];

                // Interactive ARIA roles that make elements programmatically interactive
                const INTERACTIVE_ROLES = [
                    'button',
                    'checkbox',
                    'combobox',
                    'gridcell',
                    'link',
                    'listbox',
                    'menuitem',
                    'menuitemcheckbox',
                    'menuitemradio',
                    'option',
                    'radio',
                    'searchbox',
                    'slider',
                    'spinbutton',
                    'switch',
                    'tab',
                    'textbox',
                    'treeitem'
                ];

                function getAccessibleName(element) {
                    // Try aria-label first
                    let name = element.getAttribute('aria-label');
                    if (name) return name;

                    // Try aria-labelledby
                    const labelledBy = element.getAttribute('aria-labelledby');
                    if (labelledBy) {
                        const labelElements = labelledBy.split(' ')
                            .map(id => document.getElementById(id))
                            .filter(el => el);
                        if (labelElements.length) {
                            return labelElements.map(el => el.textContent).join(' ');
                        }
                    }

                    // Try regular label for form elements
                    if (element.id) {
                        const label = document.querySelector(`label[for="${element.id}"]`);
                        if (label) return label.textContent;
                    }

                    // For buttons and links, try to get text content intelligently
                    if (element.tagName === 'BUTTON' || element.tagName === 'A') {
                        // Include both text content and image alt text
                        const textContent = element.textContent.trim();
                        const imgAlt = Array.from(element.getElementsByTagName('img'))
                            .map(img => img.alt)
                            .filter(alt => alt)
                            .join(' ');
                        return textContent || imgAlt || '';
                    }

                    // For inputs, use placeholder or value
                    if (element.tagName === 'INPUT') {
                        return element.value || element.placeholder || '';
                    }

                    // Use text content as fallback
                    return element.textContent.trim();
                }

                function isElementVisible(element) {
                    const style = window.getComputedStyle(element);
                    const rect = element.getBoundingClientRect();

                    // Check if element or any parent has display: none or visibility: hidden
                    let currentElement = element;
                    while (currentElement && currentElement !== document.body) {
                        const style = window.getComputedStyle(currentElement);
                        if (style.display === 'none' || style.visibility === 'hidden') {
                            return false;
                        }
                        currentElement = currentElement.parentElement;
                    }

                    return (
                        style.opacity !== '0' &&
                        rect.width > 0 &&
                        rect.height > 0 &&
                        rect.top >= 0 &&
                        rect.left >= 0 &&
                        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
                        rect.right <= (window.innerWidth || document.documentElement.clientWidth) &&
                        !element.hasAttribute('aria-hidden')
                    );
                }

                function getElementMetadata(element) {
                    const rect = element.getBoundingClientRect();
                    const style = window.getComputedStyle(element);

                    return {
                        tag: element.tagName.toLowerCase(),
                        type: element.type || '',
                        value: element.value || '',
                        checked: element.checked,
                        selected: element.selected,
                        disabled: element.disabled || element.hasAttribute('aria-disabled'),
                        required: element.required,
                        readOnly: element.readOnly,
                        bounds: {
                            x: rect.x,
                            y: rect.y,
                            width: rect.width,
                            height: rect.height,
                            top: rect.top,
                            right: rect.right,
                            bottom: rect.bottom,
                            left: rect.left
                        },
                        styles: {
                            backgroundColor: style.backgroundColor,
                            color: style.color,
                            fontSize: style.fontSize,
                            fontWeight: style.fontWeight
                        }
                    };
                }

                const elements = [];
                let index = 0;

                // Find elements by native interactive elements
                INTERACTIVE_ELEMENTS.forEach(selector => {
                    document.querySelectorAll(selector).forEach(element => {
                        if (isElementVisible(element)) {
                            const name = getAccessibleName(element);
                            if (name || element.tagName === 'INPUT') {  // Always include form inputs
                                elements.push({
                                    index: index++,
                                    element: element,
                                    role: element.getAttribute('role') || element.tagName.toLowerCase(),
                                    name: name,
                                    selector: `[aria-index="${index-1}"]`,
                                    metadata: getElementMetadata(element)
                                });
                                element.setAttribute('aria-index', (index-1).toString());
                            }
                        }
                    });
                });

                // Find elements by ARIA roles
                INTERACTIVE_ROLES.forEach(role => {
                    document.querySelectorAll(`[role="${role}"]`).forEach(element => {
                        if (isElementVisible(element) && !elements.find(e => e.element === element)) {
                            const name = getAccessibleName(element);
                            if (name) {
                                elements.push({
                                    index: index++,
                                    element: element,
                                    role: role,
                                    name: name,
                                    selector: `[aria-index="${index-1}"]`,
                                    metadata: getElementMetadata(element)
                                });
                                element.setAttribute('aria-index', (index-1).toString());
                            }
                        }
                    });
                });

                // Create a text representation
                const textRepresentation = elements.map(el => {
                    let desc = `[${el.index}] ${el.role}`;
                    if (el.name) {
                        desc += `: ${el.name}`;
                    }
                    if (el.metadata.type) {
                        desc += ` (type: ${el.metadata.type})`;
                    }
                    if (el.metadata.disabled) {
                        desc += ' [disabled]';
                    }
                    if (el.metadata.required) {
                        desc += ' [required]';
                    }
                    return desc;
                }).join('\\n');

                return {
                    elements: elements,
                    textRepresentation: textRepresentation
                };
            }

            return findInteractiveElements();
        }""")

    async def handle_playwright_get_aria_snapshot(self):
        """Get a snapshot of all ARIA interactive elements on the page."""
        await self.ensure_browser()
        try:
            result = await self._inject_aria_helpers()
            self._interactive_elements = result['elements']
            return {
                "success": True,
                "elements": result['elements'],
                "text_representation": result['textRepresentation']
            }
        except Exception as e:
            logger.error(f"Get ARIA snapshot failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_playwright_click_aria(self, index: int):
        """Click an element by its ARIA index."""
        await self.ensure_browser()
        try:
            if not self._interactive_elements:
                await self.handle_playwright_get_aria_snapshot()

            if 0 <= index < len(self._interactive_elements):
                element = self._interactive_elements[index]
                await self.page.click(element['selector'])
                return {"success": True}
            else:
                return {"success": False, "error": f"Invalid ARIA element index: {index}"}
        except Exception as e:
            logger.error(f"Click ARIA element failed: {e}")
            return {"success": False, "error": str(e)}

    async def handle_smart_click(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Smart click that cascades through different strategies.

        Args:
            target: Text or selector to click
            options: Additional options like timeout, force, etc.
        """
        options = options or {}
        timeout = options.get('timeout', 10000)
        start_time = time.time()

        # 1. Try ARIA first (default strategy)
        try:
            snapshot = await self.handle_playwright_get_aria_snapshot()
            if snapshot["success"]:
                for el in snapshot["elements"]:
                    if target.lower() in str(el["name"]).lower():
                        result = await self.handle_playwright_click_aria(el["index"])
                        if result["success"]:
                            return {
                                "success": True,
                                "strategy": "aria",
                                "element": el,
                                "time_taken": time.time() - start_time
                            }
        except Exception as e:
            logger.debug(f"ARIA strategy failed: {e}")

        # 2. Try MacOS/VNC screenshot approach
        try:
            # Import here to avoid circular dependency
            from mcp_remote_macos_use.server import MCPServer
            server = MCPServer()

            # Take screenshot and find text
            result = await server.handle_request("remote_macos_find_and_click_text", {
                "text": target,
                "timeout": timeout
            })

            if result.get("success"):
                return {
                    "success": True,
                    "strategy": "vnc",
                    "coordinates": result.get("coordinates"),
                    "time_taken": time.time() - start_time
                }
        except Exception as e:
            logger.debug(f"VNC strategy failed: {e}")

        # 3. Fallback to Playwright DOM
        try:
            # Try different Playwright selectors
            selectors = [
                f'text="{target}"',  # Exact text match
                f'text="{target}" i',  # Case-insensitive
                f':text-is("{target}")',  # Exact text content
                f':text-contains("{target}")',  # Contains text
                f'[aria-label*="{target}" i]',  # Aria label contains
                f'[placeholder*="{target}" i]',  # Placeholder contains
                f'[title*="{target}" i]'  # Title contains
            ]

            for selector in selectors:
                try:
                    await self.page.click(selector, timeout=timeout/len(selectors))
                    return {
                        "success": True,
                        "strategy": "playwright",
                        "selector": selector,
                        "time_taken": time.time() - start_time
                    }
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Playwright strategy failed: {e}")

        return {
            "success": False,
            "error": f"Could not find element matching '{target}' using any strategy",
            "time_taken": time.time() - start_time
        }

    async def handle_smart_type(self, text: str, target: str = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Smart type that cascades through different strategies.

        Args:
            text: Text to type
            target: Optional target field identifier (placeholder, label, etc.)
            options: Additional options like timeout, force, etc.
        """
        options = options or {}
        timeout = options.get('timeout', 10000)
        start_time = time.time()

        # 1. Try ARIA first if we have a target
        if target:
            try:
                snapshot = await self.handle_playwright_get_aria_snapshot()
                if snapshot["success"]:
                    for el in snapshot["elements"]:
                        if (target.lower() in str(el["name"]).lower() and
                            el["metadata"]["tag"] in ["input", "textarea"]):
                            await self.page.click(el["selector"])
                            await self.page.type(el["selector"], text)
                            return {
                                "success": True,
                                "strategy": "aria",
                                "element": el,
                                "time_taken": time.time() - start_time
                            }
            except Exception as e:
                logger.debug(f"ARIA strategy failed: {e}")

        # 2. Try MacOS/VNC approach if we have a target
        if target:
            try:
                from mcp_remote_macos_use.server import MCPServer
                server = MCPServer()

                # Find and click the field
                result = await server.handle_request("remote_macos_find_and_click_text", {
                    "text": target,
                    "timeout": timeout
                })

                if result.get("success"):
                    # Type the text
                    await server.handle_request("remote_macos_type_text", {
                        "text": text
                    })
                    return {
                        "success": True,
                        "strategy": "vnc",
                        "coordinates": result.get("coordinates"),
                        "time_taken": time.time() - start_time
                    }
            except Exception as e:
                logger.debug(f"VNC strategy failed: {e}")

        # 3. Fallback to Playwright DOM
        try:
            selectors = []
            if target:
                selectors.extend([
                    f'input[placeholder*="{target}" i]',
                    f'textarea[placeholder*="{target}" i]',
                    f'input[aria-label*="{target}" i]',
                    f'textarea[aria-label*="{target}" i]',
                    f'label:text-is("{target}") input',
                    f'label:text-contains("{target}") input'
                ])

            # Add focused element as last resort
            selectors.append(':focus')

            for selector in selectors:
                try:
                    await self.page.click(selector, timeout=timeout/len(selectors))
                    await self.page.type(selector, text)
                    return {
                        "success": True,
                        "strategy": "playwright",
                        "selector": selector,
                        "time_taken": time.time() - start_time
                    }
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Playwright strategy failed: {e}")

        return {
            "success": False,
            "error": f"Could not type text{' in ' + target if target else ''}",
            "time_taken": time.time() - start_time
        }

    @property
    def tool_definitions(self) -> Dict[str, Dict[str, Any]]:
        defs = {
            "playwright_navigate": {
                "description": "Navigate to a URL in the browser",
                "parameters": {
                    "url": {"type": "string", "description": "URL to navigate to"},
                    "browserType": {"type": "string", "enum": ["chromium", "firefox", "webkit"], "description": "Browser type to use", "default": "chromium"},
                    "width": {"type": "integer", "description": "Viewport width in pixels", "default": 1280},
                    "height": {"type": "integer", "description": "Viewport height in pixels", "default": 720},
                    "timeout": {"type": "integer", "description": "Navigation timeout in milliseconds"},
                    "waitUntil": {"type": "string", "description": "Navigation wait condition"},
                    "headless": {"type": "boolean", "description": "Run browser in headless mode", "default": False}
                },
                "required": ["url"]
            },
            "playwright_screenshot": {
                "description": "Take a screenshot of the current page or a specific element",
                "parameters": {
                    "name": {"type": "string", "description": "Name for the screenshot"},
                    "selector": {"type": "string", "description": "CSS selector for element to screenshot"},
                    "width": {"type": "integer", "description": "Width in pixels", "default": 800},
                    "height": {"type": "integer", "description": "Height in pixels", "default": 600},
                    "storeBase64": {"type": "boolean", "description": "Store screenshot in base64 format", "default": True},
                    "fullPage": {"type": "boolean", "description": "Store screenshot of the entire page", "default": False},
                    "savePng": {"type": "boolean", "description": "Save screenshot as PNG file", "default": False},
                    "downloadsDir": {"type": "string", "description": "Custom downloads directory path"}
                },
                "required": ["name"]
            },
            "playwright_click": {
                "description": "Click an element on the page",
                "parameters": {
                    "selector": {"type": "string", "description": "CSS selector for the element to click"}
                },
                "required": ["selector"]
            },
            "playwright_iframe_click": {
                "description": "Click an element in an iframe on the page",
                "parameters": {
                    "iframeSelector": {"type": "string", "description": "CSS selector for the iframe"},
                    "selector": {"type": "string", "description": "CSS selector for the element to click"}
                },
                "required": ["iframeSelector", "selector"]
            },
            "playwright_fill": {
                "description": "Fill out an input field",
                "parameters": {
                    "selector": {"type": "string", "description": "CSS selector for input field"},
                    "value": {"type": "string", "description": "Value to fill"}
                },
                "required": ["selector", "value"]
            },
            "playwright_select": {
                "description": "Select an element on the page with Select tag",
                "parameters": {
                    "selector": {"type": "string", "description": "CSS selector for element to select"},
                    "value": {"type": "string", "description": "Value to select"}
                },
                "required": ["selector", "value"]
            },
            "playwright_hover": {
                "description": "Hover an element on the page",
                "parameters": {
                    "selector": {"type": "string", "description": "CSS selector for element to hover"}
                },
                "required": ["selector"]
            },
            "playwright_evaluate": {
                "description": "Execute JavaScript in the browser console",
                "parameters": {
                    "script": {"type": "string", "description": "JavaScript code to execute"}
                },
                "required": ["script"]
            },
            "playwright_console_logs": {
                "description": "Retrieve console logs from the browser with filtering options",
                "parameters": {
                    "type": {
                        "type": "string",
                        "enum": ["all", "error", "warning", "log", "info", "debug"],
                        "description": "Type of logs to retrieve"
                    },
                    "search": {"type": "string", "description": "Text to search for in logs"},
                    "limit": {"type": "integer", "description": "Maximum number of logs to return"},
                    "clear": {"type": "boolean", "description": "Whether to clear logs after retrieval"}
                }
            },
            "playwright_get": {
                "description": "Perform an HTTP GET request",
                "parameters": {
                    "url": {"type": "string", "description": "URL to perform GET operation"}
                },
                "required": ["url"]
            },
            "playwright_post": {
                "description": "Perform an HTTP POST request",
                "parameters": {
                    "url": {"type": "string", "description": "URL to perform POST operation"},
                    "value": {"type": "string", "description": "Data to post in the body"},
                    "token": {"type": "string", "description": "Bearer token for authorization"},
                    "headers": {"type": "object", "description": "Additional headers"}
                },
                "required": ["url", "value"]
            },
            "playwright_expect_response": {
                "description": "Ask Playwright to start waiting for a HTTP response",
                "parameters": {
                    "id": {"type": "string", "description": "Unique identifier for this response wait"},
                    "url": {"type": "string", "description": "URL pattern to match"}
                },
                "required": ["id", "url"]
            },
            "playwright_assert_response": {
                "description": "Wait for and validate a previously initiated HTTP response wait operation",
                "parameters": {
                    "id": {"type": "string", "description": "Identifier of the expected response"},
                    "value": {"type": "string", "description": "Expected response body content"}
                },
                "required": ["id"]
            },
            "playwright_custom_user_agent": {
                "description": "Set a custom User Agent for the browser",
                "parameters": {
                    "userAgent": {"type": "string", "description": "Custom User Agent string"}
                },
                "required": ["userAgent"]
            },
            "playwright_get_visible_text": {
                "description": "Get the visible text content of the current page",
                "parameters": {}
            },
            "playwright_get_visible_html": {
                "description": "Get the HTML content of the current page",
                "parameters": {}
            },
            "playwright_go_back": {
                "description": "Navigate back in browser history",
                "parameters": {}
            },
            "playwright_go_forward": {
                "description": "Navigate forward in browser history",
                "parameters": {}
            },
            "playwright_drag": {
                "description": "Drag an element to a target location",
                "parameters": {
                    "sourceSelector": {"type": "string", "description": "CSS selector for element to drag"},
                    "targetSelector": {"type": "string", "description": "CSS selector for target location"}
                },
                "required": ["sourceSelector", "targetSelector"]
            },
            "playwright_press_key": {
                "description": "Press a keyboard key",
                "parameters": {
                    "key": {"type": "string", "description": "Key to press"},
                    "selector": {"type": "string", "description": "Optional element to focus"}
                },
                "required": ["key"]
            },
            "playwright_save_as_pdf": {
                "description": "Save the current page as a PDF file",
                "parameters": {
                    "outputPath": {"type": "string", "description": "Directory path for PDF"},
                    "filename": {"type": "string", "description": "Name of the PDF file"},
                    "format": {"type": "string", "description": "Page format (e.g. 'A4')"},
                    "printBackground": {"type": "boolean", "description": "Print background graphics"},
                    "margin": {
                        "type": "object",
                        "description": "Page margins",
                        "properties": {
                            "top": {"type": "string"},
                            "right": {"type": "string"},
                            "bottom": {"type": "string"},
                            "left": {"type": "string"}
                        }
                    }
                },
                "required": ["outputPath"]
            },
            "playwright_get_interactive_elements": {
                "description": "Get a compact representation of all interactive elements on the page",
                "parameters": {}
            },
            "playwright_click_interactive": {
                "description": "Click an interactive element by its index",
                "parameters": {
                    "index": {"type": "integer", "description": "Index of the element to click"}
                },
                "required": ["index"]
            },
            "playwright_get_aria_snapshot": {
                "description": "Get a snapshot of all ARIA interactive elements on the page",
                "parameters": {}
            },
            "playwright_click_aria": {
                "description": "Click an element by its ARIA index",
                "parameters": {
                    "index": {"type": "integer", "description": "Index of the element to click"}
                },
                "required": ["index"]
            },
            "smart_click": {
                "description": "Smart click that tries ARIA first, then VNC, then Playwright",
                "parameters": {
                    "target": {"type": "string", "description": "Text or selector to click"},
                    "options": {
                        "type": "object",
                        "description": "Additional options like timeout",
                        "optional": True
                    }
                },
                "required": ["target"]
            },
            "smart_type": {
                "description": "Smart type that tries ARIA first, then VNC, then Playwright",
                "parameters": {
                    "text": {"type": "string", "description": "Text to type"},
                    "target": {
                        "type": "string",
                        "description": "Optional target field identifier",
                        "optional": True
                    },
                    "options": {
                        "type": "object",
                        "description": "Additional options like timeout",
                        "optional": True
                    }
                },
                "required": ["text"]
            }
        }
        return defs