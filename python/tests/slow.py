"""Opt-in marking for long-running tests, usable without pytest installed.

A slow test runs only when ``SMX_SLOW_TESTS=1`` is set, under plain unittest and under
pytest alike. Under pytest it also carries the ``slow`` marker, so ``-m slow`` selects
only those tests.
"""

from __future__ import annotations

import os
import unittest

ENABLED = os.environ.get("SMX_SLOW_TESTS") == "1"

try:
    import pytest
except ImportError:  # plain unittest: no marker is needed
    pytest = None


def slow(reason: str):
    """Skip the test unless SMX_SLOW_TESTS=1; ``reason`` says how long it takes."""

    def decorate(test):
        test = unittest.skipUnless(ENABLED, f"set SMX_SLOW_TESTS=1 ({reason})")(test)
        return pytest.mark.slow(test) if pytest is not None else test

    return decorate
