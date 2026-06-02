"""Full subnet audit example."""
import asyncio
from specter.core.engine import EngineConfig, ScannerEngine

async def main() -> None:
    """Run a subnet audit example.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of main
    >>> pass"""
    engine = ScannerEngine(EngineConfig(concurrency=100))
    try:
        result = await engine.run(['192.168.1.0/24'])
        print(result)
    finally:
        await engine.close()
if __name__ == '__main__':
    asyncio.run(main())