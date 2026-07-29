"""Visible repository fixture used only by offline conformance smoke tests."""


def should_retry(status_code: int) -> bool:
    return False


MAX_ATTEMPTS = 1
