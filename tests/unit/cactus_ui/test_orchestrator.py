import pytest

from cactus_ui.orchestrator import file_name_safe


@pytest.mark.parametrize(
    "input, expected", [("", ""), ("hello-VALID_123", "hello-VALID_123"), ("abc 123@DEF./com", "abc_123_DEF__com")]
)
def test_file_name_safe(input: str, expected: str):
    assert file_name_safe(input) == expected
