"""Send scan results to SIEM example."""
import asyncio
import json
import urllib.request
from specter.core.engine import EngineConfig, ScannerEngine

async def main() -> None:
    """Run a scan and forward results to a SIEM endpoint.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of main
    >>> pass"""
    engine = ScannerEngine(EngineConfig())
    try:
        result = await engine.run(['127.0.0.1'])
        payload = json.dumps({'devices': [d.ip for d in result.devices]}).encode('utf-8')
        req = urllib.request.Request('http://localhost:9200/specter', data=payload, method='POST')
        urllib.request.urlopen(req)
    finally:
        await engine.close()
if __name__ == '__main__':
    asyncio.run(main())