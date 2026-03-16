```python
import time
from contextlib import contextmanager


@contextmanager
def measure_latency():
    """Context manager to measure execution time of a block."""
    start = time.time()
    result = {}
    yield result
    result["latency"] = time.time() - start
```