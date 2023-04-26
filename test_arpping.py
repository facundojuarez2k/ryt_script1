import pytest
from arpping import (is_valid_ipv4, is_valid_device)


class TestARPPing:
    def test_is_valid_ipv4(self):
        assert is_valid_ipv4("192.210.14.50") is True
        assert is_valid_ipv4("200.135.48.1") is True
        assert is_valid_ipv4("0.0.0.0") is True
        assert is_valid_ipv4("255.255.255.255") is True
        assert is_valid_ipv4("300.14.2.5") is False
        assert is_valid_ipv4("300.12.5") is False
        assert is_valid_ipv4("") is False
        assert is_valid_ipv4("1.2.3.4.5") is False
        assert is_valid_ipv4("1000.2.3.4.5") is False
        assert is_valid_ipv4("abc") is False
        assert is_valid_ipv4("1,4,56.3") is False

    def test_is_valid_device(self):
        with pytest.raises(NotImplementedError):
            is_valid_device("eth0")