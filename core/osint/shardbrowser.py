#!/usr/bin/env python3
"""
ShardBrowser / ShardX anti-detect browser integration.

Source: https://github.com/ProxyShard/ShardBrowser
SDK:    vendor/shardbrowser/sdks/python/shardx/

ShardX is a Chromium 148-based anti-detect browser with engine-level
fingerprint spoofing. This module provides:
  • Profile management (create/launch/stop)
  • CDP browser automation (via patchright)
  • OSINT workflows (multi-identity recon, social media)
  • Proxy binding per profile (SOCKS5 with UDP probe)
  • Cookie import/export
  • Multi-account session isolation

The SDK auto-downloads the ShardX engine + Widevine + fingerprint
library from CDN on first use — no separate install needed.

Dependencies (pip install):
  httpx[socks]>=0.27
  patchright>=1.49
"""

import os
import sys
import time
import json
import logging
from typing import Any, Dict, List, Optional

C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_RESET  = "\033[0m"

# ── Add vendor SDK to path ──
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SDK_PATH = os.path.join(_PROJECT_ROOT, "vendor", "shardbrowser", "sdks", "python")
if _SDK_PATH not in sys.path:
    sys.path.insert(0, _SDK_PATH)


class ShardBrowserError(Exception):
    pass

class ShardBrowserNotInstalled(Exception):
    pass


def _get_sdk():
    """Import ShardX SDK lazily."""
    try:
        from shardx import ShardX
        return ShardX
    except ImportError as e:
        raise ShardBrowserNotInstalled(
            f"ShardX SDK not available: {e}\n"
            "Install deps: pip install httpx[socks] patchright\n"
            "SDK path: vendor/shardbrowser/sdks/python/"
        )


class ShardBrowser:
    """
    Anti-detect browser for OCTOPUS operations.

    Uses ShardX Python SDK (vendor/shardbrowser/sdks/python/shardx/).
    Engine auto-downloads from CDN on first use.

    Usage:
        sb = ShardBrowser()
        sb.install()  # download engine (once)

        # Launch a profile
        session = sb.launch_profile("Windows", proxy="socks5://host:port")
        print(session.cdp_url)  # ws://127.0.0.1:PORT/devtools/browser/...
        session.stop()

        # OSINT
        results = sb.osint_target("target.com")

        # Multi-account
        sessions = sb.multi_session(3, proxy_list=[...])
    """

    def __init__(self, cache_dir: str = None, profiles_dir: str = None):
        self._sdk = None
        self._cache_dir = cache_dir
        self._profiles_dir = profiles_dir or os.path.join(
            _PROJECT_ROOT, "data", "shardx-profiles"
        )
        self._sessions: Dict[str, Any] = {}  # track active sessions

    def _ensure_sdk(self):
        """Lazy-load SDK."""
        if self._sdk is None:
            ShardX = _get_sdk()
            self._sdk = ShardX(
                cache_dir=self._cache_dir,
                profiles_dir=self._profiles_dir,
            )
        return self._sdk

    # ═══════════════════════════════════════════════
    # INSTALLATION
    # ═══════════════════════════════════════════════

    def install(self) -> bool:
        """Download ShardX engine + Widevine + fingerprints from CDN."""
        try:
            sdk = self._ensure_sdk()
            print(f"{C_CYAN}[*] Installing ShardX engine...{C_RESET}")
            sdk.runtime.install()
            print(f"{C_GREEN}[+] ShardX installed to: {sdk.runtime._cache_dir}{C_RESET}")
            return True
        except Exception as e:
            print(f"{C_RED}[!] Install failed: {e}{C_RESET}")
            return False

    def is_available(self) -> bool:
        """Check if ShardX SDK is importable and engine is installed."""
        try:
            sdk = self._ensure_sdk()
            return sdk.runtime.is_installed() if hasattr(sdk.runtime, 'is_installed') else True
        except Exception as e:
            return False

    # ═══════════════════════════════════════════════
    # PROFILES
    # ═══════════════════════════════════════════════

    def list_profiles(self, platform: str = None) -> List[str]:
        """List available fingerprint profiles."""
        sdk = self._ensure_sdk()
        return sdk.list_profiles(platform=platform)

    def random_profile(self, platform: str = None):
        """Get a random profile, optionally filtered by platform."""
        sdk = self._ensure_sdk()
        return sdk.random_profile(platform=platform)

    # ═══════════════════════════════════════════════
    # LAUNCH
    # ═══════════════════════════════════════════════

    def launch_profile(self, fingerprint=None, *, platform: str = "Windows",
                       proxy: str = None, headless: bool = False,
                       randomize: bool = True, cdp: bool = True,
                       webrtc: str = "auto", **kwargs) -> Any:
        """
        Launch an isolated browser profile.

        Args:
            fingerprint: profile id, Profile, dict, or None (random)
            platform: filter for random profile ("Windows"/"macOS"/"Linux")
            proxy: "socks5://user:pass@host:port" or "http://host:port"
            headless: run without GUI
            randomize: re-randomize hardware fingerprint
            cdp: enable Chrome DevTools Protocol
            webrtc: "auto" | "block" | "tcp_only"

        Returns:
            BrowserSession with .cdp_url, .pid, .geo, etc.
        """
        sdk = self._ensure_sdk()
        session = sdk.launch(
            fingerprint=fingerprint,
            platform=platform,
            randomize=randomize,
            proxy=proxy,
            headless=headless,
            cdp=cdp,
            webrtc=webrtc,
            **kwargs,
        )
        # Track session
        sid = f"shard_{int(time.time())}_{id(session)}"
        self._sessions[sid] = session
        print(f"  {C_GREEN}[+] ShardX profile launched (CDP: {session.cdp_url}){C_RESET}")
        return session

    def stop_session(self, session):
        """Stop a browser session."""
        try:
            session.stop()
        except Exception as e:
            print(f"  {C_YELLOW}[!] Stop error: {e}{C_RESET}")

    def stop_all(self):
        """Stop all tracked sessions."""
        for sid, sess in list(self._sessions.items()):
            try:
                sess.stop()
            except Exception as _exc:
                logging.debug(f"Suppressed in shardbrowser.py: {_exc}")
        self._sessions.clear()

    # ═══════════════════════════════════════════════
    # MULTI-SESSION (multi-account)
    # ═══════════════════════════════════════════════

    def multi_session(self, count: int = 3, proxy_list: List[str] = None,
                      platform: str = "Windows", **kwargs) -> List[Any]:
        """
        Launch multiple isolated browser sessions.
        Each gets a unique fingerprint + optional unique proxy.

        Args:
            count: number of sessions to launch
            proxy_list: list of proxy URLs (one per session)
            platform: fingerprint platform filter

        Returns:
            list of BrowserSession objects
        """
        sessions = []
        for i in range(count):
            proxy = proxy_list[i] if proxy_list and i < len(proxy_list) else None
            try:
                sess = self.launch_profile(
                    platform=platform,
                    proxy=proxy,
                    randomize=True,
                    **kwargs,
                )
                sessions.append(sess)
                print(f"  {C_GREEN}[+] Session {i+1}/{count} launched{C_RESET}")
            except Exception as e:
                print(f"  {C_RED}[!] Session {i+1}/{count} failed: {e}{C_RESET}")
        return sessions

    # ═══════════════════════════════════════════════
    # PROXY VALIDATION
    # ═══════════════════════════════════════════════

    def check_proxy(self, proxy_url: str) -> dict:
        """
        Validate a proxy: UDP probe, geo lookup, QUIC/WebRTC policy.

        Returns:
            {"udp_ms": float, "geo": GeoInfo, "would_enable_quic": bool,
             "would_set_webrtc": "auto"|"tcp_only"}
        """
        sdk = self._ensure_sdk()
        return sdk.check_proxy(proxy_url)

    # ═══════════════════════════════════════════════
    # OSINT WORKFLOWS
    # ═══════════════════════════════════════════════

    def osint_target(self, target: str, engines: List[str] = None,
                     proxy: str = None, headless: bool = True) -> dict:
        """
        OSINT research with isolated browser profiles per search engine.
        Prevents fingerprint correlation between searches.

        Args:
            target: search query (domain, name, email, etc.)
            engines: list of engines (google, bing, duckduckgo, yandex, shodan)
            proxy: shared proxy for all sessions
            headless: run headless

        Returns:
            {engine: {url, content_length, content, screenshot_path}}
        """
        if engines is None:
            engines = ["google", "bing", "duckduckgo"]

        search_urls = {
            "google": f"https://www.google.com/search?q={target}",
            "bing": f"https://www.bing.com/search?q={target}",
            "duckduckgo": f"https://duckduckgo.com/?q={target}",
            "yandex": f"https://yandex.com/search/?text={target}",
            "shodan": f"https://www.shodan.io/search?query={target}",
        }

        results = {}
        for engine in engines:
            url = search_urls.get(engine)
            if not url:
                continue

            print(f"  {C_CYAN}[*] OSINT {engine}: {target}{C_RESET}")
            session = None
            try:
                session = self.launch_profile(
                    platform="Windows",
                    proxy=proxy,
                    headless=headless,
                    randomize=True,
                )

                # Use patchright via CDP
                import asyncio
                try:
                    content = asyncio.run(
                        self._browse_async(session.cdp_url, url)
                    )
                except RuntimeError:
                    # Fallback if already in async context
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        content = pool.submit(
                            asyncio.run,
                            self._browse_async(session.cdp_url, url)
                        ).result(timeout=30)

                results[engine] = {
                    "url": url,
                    "content_length": len(content),
                    "content": content[:10000],
                }
                print(f"  {C_GREEN}[+] {engine}: {len(content)} bytes{C_RESET}")

            except Exception as e:
                results[engine] = {"error": str(e)}
                print(f"  {C_RED}[!] {engine}: {e}{C_RESET}")
            finally:
                if session:
                    try:
                        session.stop()
                    except Exception as _exc:
                        logging.debug(f"Suppressed in shardbrowser.py: {_exc}")

        return results

    def social_recon(self, name: str, platforms: List[str] = None,
                     proxy: str = None) -> dict:
        """
        Social media recon with isolated profiles per platform.

        Args:
            name: target name/username
            platforms: list of platforms to check

        Returns:
            {platform: {url, content_length, found}}
        """
        if platforms is None:
            platforms = ["linkedin", "twitter", "github"]

        platform_urls = {
            "linkedin": f"https://www.linkedin.com/search/results/people/?keywords={name}",
            "twitter": f"https://x.com/search?q={name}&f=user",
            "github": f"https://github.com/search?q={name}&type=users",
            "facebook": f"https://www.facebook.com/search/people/?q={name}",
            "instagram": f"https://www.instagram.com/{name}/",
        }

        results = {}
        for plat in platforms:
            url = platform_urls.get(plat)
            if not url:
                continue

            session = None
            try:
                session = self.launch_profile(
                    platform="Windows", proxy=proxy,
                    headless=True, randomize=True,
                )
                import asyncio
                try:
                    content = asyncio.run(
                        self._browse_async(session.cdp_url, url, wait=4)
                    )
                except RuntimeError:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        content = pool.submit(
                            asyncio.run,
                            self._browse_async(session.cdp_url, url, wait=4)
                        ).result(timeout=30)
                results[plat] = {
                    "url": url,
                    "content_length": len(content),
                    "found": len(content) > 1000,
                }
            except Exception as e:
                results[plat] = {"error": str(e)}
            finally:
                if session:
                    try:
                        session.stop()
                    except Exception as _exc:
                        logging.debug(f"Suppressed in shardbrowser.py: {_exc}")

        return results

    # ═══════════════════════════════════════════════
    # BROWSE HELPERS
    # ═══════════════════════════════════════════════

    async def _browse_async(self, cdp_url: str, url: str, wait: float = 3) -> str:
        """Navigate to URL via CDP and return page content."""
        try:
            from patchright.async_api import async_playwright
        except ImportError:
            # Fallback: httpx
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                r = await client.get(url)
                return r.text

        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(cdp_url)
            ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
            page = await ctx.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(int(wait * 1000))
            content = await page.content()
            await page.close()
            await browser.close()
            return content

    def browse_sync(self, session, url: str, wait: float = 3) -> str:
        """Synchronous browse using an active session."""
        import asyncio
        try:
            return asyncio.run(self._browse_async(session.cdp_url, url, wait))
        except RuntimeError:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run, self._browse_async(session.cdp_url, url, wait)
                ).result(timeout=30)

    async def screenshot_async(self, cdp_url: str, url: str,
                                output: str = None) -> bytes:
        """Take a full-page screenshot."""
        from patchright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(cdp_url)
            ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
            page = await ctx.new_page()
            if url:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(2000)
            data = await page.screenshot(full_page=True)
            if output:
                with open(output, "wb") as f:
                    f.write(data)
            await page.close()
            await browser.close()
            return data

    # ═══════════════════════════════════════════════
    # AUTHENTICATED BROWSE (cookie injection)
    # ═══════════════════════════════════════════════

    async def _browse_with_cookies_async(
        self, cdp_url: str, url: str,
        cookies: list, wait: float = 5,
        screenshot_path: str = None,
    ) -> dict:
        """Navigate to URL with pre-injected cookies via CDP.

        Args:
            cdp_url: CDP websocket URL from ShardX session
            url: target URL to navigate to
            cookies: list of cookie dicts: [{name, value, domain, path, ...}]
            wait: seconds to wait after page load
            screenshot_path: optional path to save screenshot

        Returns:
            {content, title, url_final, cookies_after, screenshot}
        """
        try:
            from patchright.async_api import async_playwright
        except ImportError:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                jar_cookies = {c["name"]: c["value"] for c in cookies}
                r = await client.get(url, cookies=jar_cookies)
                return {"content": r.text, "title": "", "url_final": str(r.url),
                        "status_code": r.status_code}

        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(cdp_url)
            ctx = browser.contexts[0] if browser.contexts else await browser.new_context()

            # Inject cookies BEFORE navigation
            await ctx.add_cookies(cookies)

            page = await ctx.new_page()
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            await page.wait_for_timeout(int(wait * 1000))

            content = await page.content()
            title = await page.title()
            final_url = page.url

            # Grab cookies after navigation (may have new ones)
            cookies_after = await ctx.cookies()

            result = {
                "content": content,
                "title": title,
                "url_final": final_url,
                "status_code": resp.status if resp else 0,
                "cookies_after": [
                    {"name": c["name"], "value": c["value"][:40],
                     "domain": c.get("domain", "")}
                    for c in cookies_after[:20]
                ],
            }

            if screenshot_path:
                data = await page.screenshot(full_page=True)
                with open(screenshot_path, "wb") as f:
                    f.write(data)
                result["screenshot"] = screenshot_path

            await page.close()
            await browser.close()
            return result

    def browse_with_cookies(
        self, url: str, cookies: list,
        proxy: str = None, headless: bool = True,
        screenshot_path: str = None, wait: float = 5,
    ) -> dict:
        """
        Open URL in anti-detect browser with injected cookies.

        Typical use: after cPanel exploit, open the authenticated panel.

        Args:
            url: target URL (e.g. https://host:2087/cpsessXXX/...)
            cookies: [{name: "whostmgrsession", value: ":xJEK...", domain: "host"}]
            proxy: optional SOCKS5 proxy
            headless: run headless (False = visible browser)
            screenshot_path: save screenshot
            wait: seconds to wait for page

        Returns:
            {content, title, url_final, cookies_after, screenshot}
        """
        import asyncio

        session = self.launch_profile(
            platform="Windows", proxy=proxy,
            headless=headless, randomize=True,
        )

        try:
            try:
                result = asyncio.run(
                    self._browse_with_cookies_async(
                        session.cdp_url, url, cookies,
                        wait=wait, screenshot_path=screenshot_path,
                    )
                )
            except RuntimeError:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(
                        asyncio.run,
                        self._browse_with_cookies_async(
                            session.cdp_url, url, cookies,
                            wait=wait, screenshot_path=screenshot_path,
                        )
                    ).result(timeout=60)
            return result
        finally:
            try:
                session.stop()
            except Exception as _exc:
                logging.debug(f"Suppressed in shardbrowser.py: {_exc}")

    # ═══════════════════════════════════════════════
    # STATUS
    # ═══════════════════════════════════════════════

    def get_status(self) -> dict:
        """Get SDK status info."""
        try:
            sdk = self._ensure_sdk()
            profiles = sdk.list_profiles()
            return {
                "installed": True,
                "profiles_count": len(profiles),
                "active_sessions": len(self._sessions),
                "profiles_dir": self._profiles_dir,
            }
        except Exception as e:
            return {"installed": False, "error": str(e)}

