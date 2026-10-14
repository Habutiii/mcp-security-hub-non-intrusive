"""Argument values cannot smuggle flags, shell syntax, or unbounded work."""

import pytest

from adapters.input_validation import bounded_int, host, http_url, strict_bool, tcp_ports


def test_bounded_scalars_reject_string_and_boolean_coercion():
    assert bounded_int(5, "rate", 1, 50) == 5
    assert strict_bool(False, "reason") is False
    for value in (True, "5", 51):
        with pytest.raises(ValueError):
            bounded_int(value, "rate", 1, 50)
    with pytest.raises(ValueError):
        strict_bool("false", "reason")


@pytest.mark.parametrize("value", ["--script", "example.com\n--script=unsafe", "-oX", "example.com;whoami"])
def test_host_rejects_option_and_command_text(value):
    with pytest.raises(ValueError):
        host(value)


def test_url_is_one_bounded_http_argument():
    assert http_url("https://example.com/a?x=1") == "https://example.com/a?x=1"
    for value in ("-u", "file:///etc/passwd", "https://a:b@example.com", "https://example.com\n-H: evil"):
        with pytest.raises(ValueError):
            http_url(value)


def test_port_spec_cannot_inject_an_option_or_expand_without_limit():
    assert tcp_ports("22,80,443,8000-8010") == "22,80,443,8000-8010"
    for value in ("22,--script=unsafe", "1-2000", "0", "443-80", "80;id", "U:53"):
        with pytest.raises(ValueError):
            tcp_ports(value)
