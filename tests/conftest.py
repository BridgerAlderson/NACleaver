import os

import pytest

from core.utils import Cleanup


@pytest.fixture(autouse=True)
def reset_cleanup_state():
    Cleanup._reset_memory()
    yield
    for path in list(Cleanup._temp_files):
        try:
            os.remove(path)
        except OSError:
            pass
    Cleanup._reset_memory()
