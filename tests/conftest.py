import asyncio
import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tmp_db_path():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d) / "test.db"
