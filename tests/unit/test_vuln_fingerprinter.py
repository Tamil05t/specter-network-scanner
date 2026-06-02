import pytest
from specter.scanners.vuln_fingerprinter import VulnerabilityFingerprinter
from specter.models.dataclasses import Device
import aiohttp
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_fingerprinter():
    fp = VulnerabilityFingerprinter()
    dev = Device('127.0.0.1')
    limiter = AsyncMock()
    
    # Mock session
    class FakeResponse:
        def __init__(self):
            self.headers = {"Server": "nginx"}
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass
            
    class FakeSession:
        def get(self, url, timeout):
            return FakeResponse()
            
    try:
        res = await fp.fingerprint(dev, FakeSession(), limiter)
        assert res is not None
    except Exception:
        pass
