import re
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "frontend" / "app_flagship.py").read_text()


def test_no_div_wrappers_split_across_streamlit_calls():
    # a <div> opened in one st.markdown and closed in another renders as an empty box
    assert not re.search(r'st\.markdown\("</div>"', SRC)
    assert not re.search(r"st\.markdown\(\"<div class='(surface|scanner-box)'>\"\s*,\s*unsafe", SRC)


def test_title_not_clipped_and_typo_fixed():
    assert "padding: 3.4rem 2.4rem 3rem" in SRC
    assert "COMPPhISH" not in SRC and "COMPHISH" in SRC


def test_small_text_is_brighter():
    assert ".info-key, .metric-foot, .section-meta" in SRC and "#9aa6bd" in SRC
    assert "#77839b" not in SRC
