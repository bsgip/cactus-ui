import pytest

from cactus_ui.common import find_first


@pytest.mark.parametrize(
    "items, matcher, expected",
    [
        ([], lambda x: True, None),
        ([], lambda x: False, None),
        ([1, 2, 3], lambda x: x == 2, 2),
        ([("a", [1, 2, 3]), ("b", [1]), ("c", [4, 5])], lambda x: x[0] == "c", ("c", [4, 5])),
    ],
)
def test_find_first(items, matcher, expected):
    actual = find_first(items, matcher)
    assert actual == expected
