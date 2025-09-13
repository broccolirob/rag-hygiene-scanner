import pytest
from rag_hygiene_scan.patterns import severity_rank, SEVERITY_ORDER

def test_severity_rank_ordering():
    assert severity_rank("low")  < severity_rank("med") < severity_rank("high")

def test_invalid_severity_raises():
    with pytest.raises(ValueError):
        severity_rank("critical")  # not allowed
