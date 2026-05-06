from collections.abc import Callable


def find_first[T](list_to_search: list[T], matcher: Callable[[T], bool]) -> T | None:
    for item in list_to_search:
        if matcher(item):
            return item

    return None
