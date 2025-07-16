from typing import Callable, TypeVar

T = TypeVar("T")


def find_first(list_to_search: list[T], matcher: Callable[[T], bool]) -> T | None:
    """Finds the first items matching matcher by evaluating items in list_to_search sequentially. Returns the first
    match or None if no match was found"""
    for item in list_to_search:
        if matcher(item):
            return item

    return None
