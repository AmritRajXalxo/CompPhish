from pathlib import Path

import pytest

from backend.size_cap import read_capped

ROOT = Path(__file__).resolve().parents[1]


def test_under_limit_not_truncated():
    assert read_capped([b"abc", b"def"], 10) == (b"abcdef", False)


def test_exactly_at_limit_not_truncated():
    assert read_capped([b"abc", b"def"], 6) == (b"abcdef", False)


def test_over_limit_is_cut_and_flagged():
    data, cut = read_capped([b"abcd", b"efgh"], 6)
    assert (data, cut) == (b"abcdef", True)


def test_stops_reading_an_endless_stream():
    pulled = 0

    def endless():
        nonlocal pulled
        while True:
            pulled += 1
            yield b"x" * 1000

    data, cut = read_capped(endless(), 5000)
    assert len(data) == 5000 and cut and pulled == 6


def test_empty_chunks_and_bad_limit():
    assert read_capped([b"", b"a", b""], 5) == (b"a", False)
    with pytest.raises(ValueError):
        read_capped([b"a"], 0)


def test_fetcher_caps_instead_of_rejecting_and_api_reports_it():
    fetcher = (ROOT / "backend" / "webpage_fetcher.py").read_text()
    assert "exceeds the size limit" not in fetcher and "Webpage is too large" not in fetcher
    assert "read_capped(" in fetcher and '"html_truncated": truncated' in fetcher
    assert '"html_truncated"' in (ROOT / "backend" / "main.py").read_text()
    assert "only this first part was analysed" in (ROOT / "frontend" / "app_flagship.py").read_text()
