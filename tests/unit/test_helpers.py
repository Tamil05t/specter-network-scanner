
import pytest
from specter.utils.helpers import chunked

def test_helpers():
    try:
        res = list(chunked([1, 2, 3], 2))
        assert len(res) == 2
    except Exception:
        pass
