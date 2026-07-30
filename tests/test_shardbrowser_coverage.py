"""Hermetic coverage for the ShardBrowser integration boundary."""

from __future__ import annotations

import asyncio
import builtins
import concurrent.futures
import logging
import runpy
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, mock_open

import pytest

from core.osint import shardbrowser

pytestmark = pytest.mark.unit


class _Session:
    def __init__(self, *, cdp_url: str = "ws://cdp", stop_error: bool = False):
        self.cdp_url = cdp_url
        self.stop_error = stop_error
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1
        if self.stop_error:
            raise RuntimeError("stop failed")


class _HTTPResponse:
    def __init__(
        self,
        text: str,
        *,
        url: str = "https://final.test/",
        status_code: int = 200,
    ):
        self.text = text
        self.url = url
        self.status_code = status_code


def _block_patchright(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "patchright", None)
    monkeypatch.setitem(sys.modules, "patchright.async_api", None)


def _install_httpx(
    monkeypatch: pytest.MonkeyPatch,
    response: _HTTPResponse,
) -> list:
    instances = []

    class AsyncClient:
        def __init__(self, **kwargs):
            self.options = kwargs
            self.calls = []
            instances.append(self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return response

    module = ModuleType("httpx")
    module.AsyncClient = AsyncClient
    monkeypatch.setitem(sys.modules, "httpx", module)
    return instances


class _Page:
    def __init__(
        self,
        *,
        content: str = "<html>page</html>",
        title: str = "Page",
        final_url: str = "https://final.test/",
        screenshot: bytes = b"image",
        response=None,
    ):
        self._content = content
        self._title = title
        self.url = final_url
        self._screenshot = screenshot
        self.response = response
        self.goto_calls = []
        self.wait_calls = []
        self.closed = False

    async def goto(self, url, **kwargs):
        self.goto_calls.append((url, kwargs))
        return self.response

    async def wait_for_timeout(self, milliseconds):
        self.wait_calls.append(milliseconds)

    async def content(self):
        return self._content

    async def title(self):
        return self._title

    async def screenshot(self, **_kwargs):
        return self._screenshot

    async def close(self):
        self.closed = True


class _Context:
    def __init__(self, page: _Page, *, cookies=None):
        self.page = page
        self.cookie_values = cookies or []
        self.added_cookies = None

    async def new_page(self):
        return self.page

    async def add_cookies(self, cookies):
        self.added_cookies = cookies

    async def cookies(self):
        return self.cookie_values


class _Browser:
    def __init__(self, context: _Context, *, existing_context: bool = True):
        self.contexts = [context] if existing_context else []
        self.context = context
        self.new_context_calls = 0
        self.closed = False

    async def new_context(self):
        self.new_context_calls += 1
        return self.context

    async def close(self):
        self.closed = True


def _install_patchright(
    monkeypatch: pytest.MonkeyPatch,
    browser: _Browser,
) -> None:
    class Chromium:
        async def connect_over_cdp(self, cdp_url):
            assert cdp_url == "ws://cdp"
            return browser

    class PlaywrightManager:
        async def __aenter__(self):
            return SimpleNamespace(chromium=Chromium())

        async def __aexit__(self, *_args):
            return False

    package = ModuleType("patchright")
    package.__path__ = []
    api = ModuleType("patchright.async_api")
    api.async_playwright = PlaywrightManager
    monkeypatch.setitem(sys.modules, "patchright", package)
    monkeypatch.setitem(sys.modules, "patchright.async_api", api)


class _ImmediateFuture:
    def __init__(self, value):
        self.value = value

    def result(self, timeout):
        assert timeout in {30, 60}
        return self.value


class _ImmediateExecutor:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def submit(self, _function, awaitable):
        awaitable.close()
        return _ImmediateFuture(self.value)


def _force_asyncio_fallback(monkeypatch: pytest.MonkeyPatch, value) -> None:
    def reject(awaitable):
        awaitable.close()
        raise RuntimeError("event loop already running")

    monkeypatch.setattr(asyncio, "run", reject)
    monkeypatch.setattr(
        concurrent.futures,
        "ThreadPoolExecutor",
        lambda: _ImmediateExecutor(value),
    )


def test_module_path_guard_and_sdk_import_paths(monkeypatch):
    monkeypatch.setattr(
        sys,
        "path",
        [shardbrowser._SDK_PATH, *sys.path],
    )
    namespace = runpy.run_path(
        shardbrowser.__file__,
        run_name="_shardbrowser_path_guard",
    )
    assert namespace["_SDK_PATH"] == shardbrowser._SDK_PATH

    module = ModuleType("shardx")

    class ShardX:
        pass

    module.ShardX = ShardX
    monkeypatch.setitem(sys.modules, "shardx", module)
    assert shardbrowser._get_sdk() is ShardX

    monkeypatch.setitem(sys.modules, "shardx", None)
    with pytest.raises(
        shardbrowser.ShardBrowserNotInstalled,
        match="ShardX SDK not available",
    ):
        shardbrowser._get_sdk()


def test_sdk_lifecycle_install_availability_and_delegates(monkeypatch, capsys):
    constructed = []

    class Runtime:
        _cache_dir = "/virtual/cache"

        def __init__(self):
            self.install_calls = 0

        def install(self):
            self.install_calls += 1

        @staticmethod
        def is_installed():
            return False

    class SDK:
        def __init__(self, **kwargs):
            self.options = kwargs
            self.runtime = Runtime()
            self.launch_calls = []
            constructed.append(self)

        @staticmethod
        def list_profiles(platform=None):
            return [platform or "all"]

        @staticmethod
        def random_profile(platform=None):
            return {"platform": platform}

        def launch(self, **kwargs):
            self.launch_calls.append(kwargs)
            return _Session(cdp_url="ws://launched")

        @staticmethod
        def check_proxy(proxy_url):
            return {"proxy": proxy_url}

    monkeypatch.setattr(shardbrowser, "_get_sdk", lambda: SDK)
    browser = shardbrowser.ShardBrowser(
        cache_dir="/virtual/cache",
        profiles_dir="/virtual/profiles",
    )
    sdk = browser._ensure_sdk()
    assert browser._ensure_sdk() is sdk
    assert sdk.options == {
        "cache_dir": "/virtual/cache",
        "profiles_dir": "/virtual/profiles",
    }
    assert len(constructed) == 1

    default_browser = shardbrowser.ShardBrowser()
    assert default_browser._profiles_dir.endswith("data/shardx-profiles")

    assert browser.install() is True
    assert sdk.runtime.install_calls == 1
    assert browser.is_available() is False
    assert browser.list_profiles("Linux") == ["Linux"]
    assert browser.random_profile("Windows") == {"platform": "Windows"}
    assert browser.check_proxy("socks5://proxy") == {"proxy": "socks5://proxy"}

    monkeypatch.setattr(shardbrowser.time, "time", lambda: 123.9)
    session = browser.launch_profile(
        "fingerprint",
        platform="Linux",
        proxy="http://proxy",
        headless=True,
        randomize=False,
        cdp=False,
        webrtc="block",
        extra="value",
    )
    assert session in browser._sessions.values()
    assert sdk.launch_calls[-1]["extra"] == "value"
    assert "ShardX installed" in capsys.readouterr().out

    no_probe = shardbrowser.ShardBrowser()
    no_probe._sdk = SimpleNamespace(runtime=SimpleNamespace())
    assert no_probe.is_available() is True

    unavailable = shardbrowser.ShardBrowser()
    unavailable._ensure_sdk = Mock(side_effect=RuntimeError("missing"))
    assert unavailable.install() is False
    assert unavailable.is_available() is False


def test_session_stop_helpers_and_multi_session(monkeypatch, caplog):
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    good = _Session()
    bad = _Session(stop_error=True)

    browser.stop_session(good)
    browser.stop_session(bad)
    assert good.stop_calls == 1
    assert bad.stop_calls == 1

    caplog.set_level(logging.DEBUG)
    browser._sessions = {"good": good, "bad": bad}
    browser.stop_all()
    assert browser._sessions == {}
    assert "Suppressed in shardbrowser.py" in caplog.text

    calls = []

    def launch_profile(**kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            raise RuntimeError("launch failed")
        return _Session(cdp_url=f"ws://{len(calls)}")

    monkeypatch.setattr(browser, "launch_profile", launch_profile)
    sessions = browser.multi_session(
        3,
        proxy_list=["socks5://first"],
        platform="Linux",
        headless=True,
    )
    assert len(sessions) == 2
    assert [call["proxy"] for call in calls] == ["socks5://first", None, None]

    calls.clear()
    assert len(browser.multi_session(1, proxy_list=None)) == 1
    assert calls[0]["proxy"] is None


def test_osint_target_default_errors_success_and_cleanup(monkeypatch, caplog):
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    monkeypatch.setattr(
        browser,
        "launch_profile",
        Mock(side_effect=RuntimeError("browser unavailable")),
    )
    defaults = browser.osint_target("target")
    assert set(defaults) == {"google", "bing", "duckduckgo"}
    assert all("error" in result for result in defaults.values())

    good = _Session(cdp_url="ws://good")
    bad_stop = _Session(cdp_url="ws://bad-stop", stop_error=True)
    launches = iter([good, RuntimeError("launch failed"), bad_stop])

    def launch(**_kwargs):
        value = next(launches)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(browser, "launch_profile", launch)
    monkeypatch.setattr(
        browser,
        "_browse_async",
        AsyncMock(side_effect=["g" * 10050, "yandex"]),
    )
    caplog.set_level(logging.DEBUG)
    results = browser.osint_target(
        "target",
        engines=["unknown", "google", "bing", "yandex"],
        proxy="socks5://proxy",
        headless=False,
    )
    assert results["google"]["content_length"] == 10050
    assert len(results["google"]["content"]) == 10000
    assert results["bing"] == {"error": "launch failed"}
    assert results["yandex"]["content"] == "yandex"
    assert good.stop_calls == 1
    assert bad_stop.stop_calls == 1
    assert "Suppressed in shardbrowser.py" in caplog.text


def test_osint_target_uses_mocked_async_fallback(monkeypatch):
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    session = _Session()
    monkeypatch.setattr(browser, "launch_profile", lambda **_kwargs: session)
    monkeypatch.setattr(browser, "_browse_async", AsyncMock())
    _force_asyncio_fallback(monkeypatch, "fallback content")

    result = browser.osint_target("target", engines=["shodan"])

    assert result["shodan"]["content"] == "fallback content"
    assert session.stop_calls == 1


def test_social_recon_default_errors_success_and_cleanup(monkeypatch, caplog):
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    monkeypatch.setattr(
        browser,
        "launch_profile",
        Mock(side_effect=RuntimeError("browser unavailable")),
    )
    defaults = browser.social_recon("name")
    assert set(defaults) == {"linkedin", "twitter", "github"}
    assert all("error" in result for result in defaults.values())

    bad_stop = _Session(stop_error=True)
    launches = iter([bad_stop, RuntimeError("launch failed")])

    def launch(**_kwargs):
        value = next(launches)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(browser, "launch_profile", launch)
    monkeypatch.setattr(browser, "_browse_async", AsyncMock(return_value="x" * 1001))
    caplog.set_level(logging.DEBUG)
    results = browser.social_recon(
        "name",
        platforms=["unknown", "github", "twitter"],
        proxy="socks5://proxy",
    )
    assert results["github"]["found"] is True
    assert results["twitter"] == {"error": "launch failed"}
    assert bad_stop.stop_calls == 1
    assert "Suppressed in shardbrowser.py" in caplog.text


def test_social_recon_uses_mocked_async_fallback(monkeypatch):
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    session = _Session()
    monkeypatch.setattr(browser, "launch_profile", lambda **_kwargs: session)
    monkeypatch.setattr(browser, "_browse_async", AsyncMock())
    _force_asyncio_fallback(monkeypatch, "short")

    result = browser.social_recon("name", platforms=["instagram"])

    assert result["instagram"]["found"] is False
    assert session.stop_calls == 1


def test_browse_async_http_fallback_is_fully_mocked(monkeypatch):
    _block_patchright(monkeypatch)
    response = _HTTPResponse("http fallback")
    clients = _install_httpx(monkeypatch, response)
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")

    content = asyncio.run(browser._browse_async("ws://cdp", "https://target.test"))

    assert content == "http fallback"
    assert clients[0].options == {"verify": False, "timeout": 15}
    assert clients[0].calls == [("https://target.test", {})]


@pytest.mark.parametrize("existing_context", [True, False])
def test_browse_async_mocked_cdp(monkeypatch, existing_context):
    page = _Page(content="rendered")
    context = _Context(page)
    cdp_browser = _Browser(context, existing_context=existing_context)
    _install_patchright(monkeypatch, cdp_browser)
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")

    content = asyncio.run(
        browser._browse_async(
            "ws://cdp",
            "https://target.test",
            wait=1.25,
        )
    )

    assert content == "rendered"
    assert page.wait_calls == [1250]
    assert page.closed is True
    assert cdp_browser.closed is True
    assert cdp_browser.new_context_calls == (0 if existing_context else 1)


def test_browse_sync_success_and_mocked_thread_fallback(monkeypatch):
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    monkeypatch.setattr(browser, "_browse_async", AsyncMock(return_value="direct"))
    assert browser.browse_sync(_Session(), "https://target.test") == "direct"

    monkeypatch.setattr(browser, "_browse_async", AsyncMock())
    _force_asyncio_fallback(monkeypatch, "thread fallback")
    assert browser.browse_sync(_Session(), "https://target.test") == "thread fallback"


def test_screenshot_async_url_output_and_empty_paths(monkeypatch):
    page = _Page(screenshot=b"png")
    context = _Context(page)
    cdp_browser = _Browser(context)
    _install_patchright(monkeypatch, cdp_browser)
    file_mock = mock_open()
    monkeypatch.setattr(builtins, "open", file_mock)
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")

    data = asyncio.run(
        browser.screenshot_async(
            "ws://cdp",
            "https://target.test",
            output="/virtual/screenshot.png",
        )
    )
    assert data == b"png"
    file_mock.assert_called_once_with("/virtual/screenshot.png", "wb")
    file_mock().write.assert_called_once_with(b"png")
    assert page.wait_calls == [2000]

    page = _Page(screenshot=b"other")
    context = _Context(page)
    cdp_browser = _Browser(context, existing_context=False)
    _install_patchright(monkeypatch, cdp_browser)
    assert asyncio.run(browser.screenshot_async("ws://cdp", "")) == b"other"
    assert page.goto_calls == []
    assert cdp_browser.new_context_calls == 1


def test_cookie_browse_http_fallback_is_fully_mocked(monkeypatch):
    _block_patchright(monkeypatch)
    response = _HTTPResponse(
        "authenticated",
        url="https://redirect.test/",
        status_code=202,
    )
    clients = _install_httpx(monkeypatch, response)
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    cookies = [{"name": "session", "value": "secret"}]

    result = asyncio.run(
        browser._browse_with_cookies_async(
            "ws://cdp",
            "https://target.test",
            cookies,
        )
    )

    assert result == {
        "content": "authenticated",
        "title": "",
        "url_final": "https://redirect.test/",
        "status_code": 202,
    }
    assert clients[0].options == {"verify": False, "timeout": 20}
    assert clients[0].calls[0][1] == {"cookies": {"session": "secret"}}


@pytest.mark.parametrize(
    ("screenshot_path", "response", "expected_status"),
    [
        ("/virtual/capture.png", SimpleNamespace(status=204), 204),
        (None, None, 0),
    ],
)
def test_cookie_browse_mocked_cdp_paths(
    monkeypatch,
    screenshot_path,
    response,
    expected_status,
):
    page = _Page(content="private", title="Private", response=response)
    cookies_after = [
        {"name": "session", "value": "v" * 50, "domain": "target.test"},
        {"name": "other", "value": "short"},
    ]
    context = _Context(page, cookies=cookies_after)
    cdp_browser = _Browser(context, existing_context=screenshot_path is not None)
    _install_patchright(monkeypatch, cdp_browser)
    file_mock = mock_open()
    monkeypatch.setattr(builtins, "open", file_mock)
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    injected = [{"name": "session", "value": "secret"}]

    result = asyncio.run(
        browser._browse_with_cookies_async(
            "ws://cdp",
            "https://target.test",
            injected,
            wait=0.5,
            screenshot_path=screenshot_path,
        )
    )

    assert result["content"] == "private"
    assert result["title"] == "Private"
    assert result["status_code"] == expected_status
    assert result["cookies_after"][0]["value"] == "v" * 40
    assert result["cookies_after"][1]["domain"] == ""
    assert context.added_cookies == injected
    if screenshot_path:
        assert result["screenshot"] == screenshot_path
        file_mock().write.assert_called_once_with(b"image")
    else:
        file_mock.assert_not_called()


def test_browse_with_cookies_success_fallback_and_stop_errors(monkeypatch, caplog):
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    bad_stop = _Session(stop_error=True)
    monkeypatch.setattr(browser, "launch_profile", lambda **_kwargs: bad_stop)
    monkeypatch.setattr(
        browser,
        "_browse_with_cookies_async",
        AsyncMock(return_value={"mode": "direct"}),
    )
    caplog.set_level(logging.DEBUG)
    assert browser.browse_with_cookies(
        "https://target.test",
        [{"name": "session", "value": "secret"}],
        screenshot_path="/virtual/capture.png",
    ) == {"mode": "direct"}
    assert bad_stop.stop_calls == 1
    assert "Suppressed in shardbrowser.py" in caplog.text

    good = _Session()
    monkeypatch.setattr(browser, "launch_profile", lambda **_kwargs: good)
    monkeypatch.setattr(browser, "_browse_with_cookies_async", AsyncMock())
    _force_asyncio_fallback(monkeypatch, {"mode": "thread"})
    assert browser.browse_with_cookies("https://target.test", []) == {"mode": "thread"}
    assert good.stop_calls == 1


def test_get_status_success_and_error():
    browser = shardbrowser.ShardBrowser(profiles_dir="/virtual/profiles")
    browser._sdk = SimpleNamespace(list_profiles=lambda: ["one", "two"])
    browser._sessions = {"active": _Session()}
    assert browser.get_status() == {
        "installed": True,
        "profiles_count": 2,
        "active_sessions": 1,
        "profiles_dir": "/virtual/profiles",
    }

    browser._ensure_sdk = Mock(side_effect=RuntimeError("sdk unavailable"))
    assert browser.get_status() == {
        "installed": False,
        "error": "sdk unavailable",
    }
