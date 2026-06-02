"""General helper utilities."""

from __future__ import annotations

from typing import Iterable, List


def chunked(items: Iterable[int], size: int) -> List[List[int]]:
    """Split an iterable into fixed-size chunks.

    Args:
        items (Iterable[int]): Iterable of integers.
        size (int): Max chunk size.

    Returns:
        List[List[int]]: List of chunks.

    Raises:
        ValueError: If size is not positive.

    Example:
        >>> chunked([1, 2, 3, 4], 2)

    Note:
        The final chunk may be smaller than the size.
    """
    if size <= 0:
        raise ValueError("size must be positive")
    chunk: List[int] = []
    output: List[List[int]] = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            output.append(chunk)
            chunk = []
    if chunk:
        output.append(chunk)
    return output
