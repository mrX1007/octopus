"""
Traffic Profiles: behavioral templates for network cadence.

Each profile defines timing distributions, chunk sizes, retry behavior,
and idle patterns that mimic specific application behaviors.

Profiles are intentionally imperfect — real applications are noisy,
retry weirdly, timeout unexpectedly, and burst strangely.
"Too perfect realism" is itself a detection signal.
"""

from core.transport.base import TrafficPolicy


def updater_profile() -> TrafficPolicy:
    """
    Background updater / sync agent.

    Behavior:
      - Long intervals between checks (30-120s)
      - Short bursts when downloading (3 requests, then cooldown)
      - Large chunks (16KB) resembling binary/package downloads
      - Occasional weird retries (like a real update client)
    """
    return TrafficPolicy(
        profile_name="updater",
        min_jitter=30.0,
        max_jitter=120.0,
        burst_size=3,
        burst_cooldown=10.0,
        chunk_size=16384,
        retry_base=2.0,
        retry_max=60.0,
        retry_jitter=3.0,
        max_retries=2,
    )


def browser_profile() -> TrafficPolicy:
    """
    Browser-like session with page loads.

    Behavior:
      - Fast bursts (loading page resources: 5-8 requests)
      - Short inter-request delays (0.05-0.5s within a burst)
      - Long pauses between "page navigations" (5-30s)
      - Small-medium chunks (4KB, like JSON API calls)
    """
    return TrafficPolicy(
        profile_name="browser",
        min_jitter=0.05,
        max_jitter=0.5,
        burst_size=6,
        burst_cooldown=15.0,
        chunk_size=4096,
        retry_base=0.5,
        retry_max=10.0,
        retry_jitter=0.3,
        max_retries=3,
    )


def scraper_profile() -> TrafficPolicy:
    """
    Web scraper / data collector.

    Behavior:
      - Periodic with moderate variance (2-8s between requests)
      - No real burst pattern (steady crawl)
      - Medium chunks (8KB)
      - Tolerant retries (scrapers expect failures)
    """
    return TrafficPolicy(
        profile_name="scraper",
        min_jitter=2.0,
        max_jitter=8.0,
        burst_size=10,  # High burst threshold = basically no bursting
        burst_cooldown=3.0,
        chunk_size=8192,
        retry_base=1.0,
        retry_max=15.0,
        retry_jitter=1.0,
        max_retries=5,
    )


def stealth_profile() -> TrafficPolicy:
    """
    Maximum stealth / low-and-slow.

    Behavior:
      - Very long intervals (60-300s)
      - No bursting at all
      - Small payloads (2KB)
      - Minimal retries (don't draw attention)
    """
    return TrafficPolicy(
        profile_name="stealth",
        min_jitter=60.0,
        max_jitter=300.0,
        burst_size=1,
        burst_cooldown=600.0,
        chunk_size=2048,
        retry_base=30.0,
        retry_max=120.0,
        retry_jitter=10.0,
        max_retries=1,
    )


# Registry for lookup by name
PROFILES = {
    "updater": updater_profile,
    "browser": browser_profile,
    "scraper": scraper_profile,
    "stealth": stealth_profile,
}


def get_profile(name: str) -> TrafficPolicy:
    """Get a traffic profile by name. Falls back to updater."""
    factory = PROFILES.get(name, updater_profile)
    return factory()
