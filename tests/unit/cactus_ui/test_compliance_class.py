from cactus_ui.compliance_class import fetch_compliance_classes


def test_fetch_compliance_classes():
    result = fetch_compliance_classes({"A", "M", "G"})
    assert ["A", "G", "M"] == [r.name for r in result]
    assert all([isinstance(r.description, str) for r in result])
    assert all([len(r.description) > 0 for r in result])

    result = fetch_compliance_classes({"FOO", "A", "M", "G"})
    assert ["A", "G", "M", "FOO"] == [r.name for r in result]
    assert all([isinstance(r.description, str) for r in result])
