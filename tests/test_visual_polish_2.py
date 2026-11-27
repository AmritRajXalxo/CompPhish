import re
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "frontend" / "app_flagship.py").read_text()


def test_chart_overrides_run_after_the_shared_layout():
    # plot_layout() sets legend and margin; an override placed before it is silently lost
    for name in ("fig", "donut"):
        assert f"{name} = plot_layout({name}, 300)" in SRC
        assert f"st.plotly_chart(plot_layout({name}" not in SRC
    assert "architecture = plot_layout(architecture, 420)" in SRC
    assert SRC.index("architecture = plot_layout(architecture, 420)") < SRC.index("margin=dict(l=18, r=96")


def test_donut_has_percent_legend_and_centre_text():
    assert "Low risk · 71%" in SRC and "High risk · 11%" in SRC and "Share of<br>sample scans" in SRC


def test_line_chart_has_axis_titles():
    assert 'xaxis_title="Day of week"' in SRC and "Scans per day (sample)" in SRC


def test_sankey_labels_larger_and_banner_short():
    assert re.search(r"textfont=dict\(size=14", SRC)
    assert "Domain intelligence, graph analysis, GA selection, fuzzy logic and SHAP are not part of it." in SRC
    assert "not represented as implemented components here" not in SRC


def test_phone_rules_present():
    assert "overflow-x:hidden" in SRC and ".metric-card{min-height:96px}" in SRC
