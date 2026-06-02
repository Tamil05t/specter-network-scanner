"""Basic single-host scan example."""
import asyncio
from specter.core.engine import EngineConfig, ScannerEngine

async def main() -> None:
    """Run a single-host scan example.

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
        print(result)
    finally:
        await engine.close()
if __name__ == '__main__':
    asyncio.run(main())