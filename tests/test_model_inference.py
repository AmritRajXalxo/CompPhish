import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# --------------------------------------------------
# 1. Configure project path
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(PROJECT_ROOT))

from backend.feature_extraction import (
    extract_url_features,
    extract_html_features,
    extract_visible_text,
)

# --------------------------------------------------
# 2. Load trained hybrid model
# --------------------------------------------------

MODEL_PATH = PROJECT_ROOT / "models" / "compphish_hybrid_model.joblib"

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model file not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

print("=" * 55)
print("COMPPHISH HYBRID MODEL INFERENCE TEST")
print("=" * 55)

print("Model:", model["model_name"])
print("Threshold:", model["threshold"])

# --------------------------------------------------
# 3. Sample website input
# --------------------------------------------------

url = "https://example.com/login?user=test"

html = """
<html>
<head>
    <title>Example Login</title>
</head>
<body>
    <h1>Account Login</h1>

    <form>
        <input type="text">
        <input type="password">
        <button>Login</button>
    </form>

    <script>
        alert("Example");
    </script>
</body>
</html>
"""

# --------------------------------------------------
# 4. Extract URL features
# --------------------------------------------------

url_features = extract_url_features(
    url,
    model["url_features"]
)

url_input = pd.DataFrame(
    [url_features],
    columns=model["url_features"]
)

# --------------------------------------------------
# 5. Extract HTML features
# --------------------------------------------------

html_features = extract_html_features(
    html,
    model["html_features"]
)

html_input = pd.DataFrame(
    [html_features],
    columns=model["html_features"]
)

# --------------------------------------------------
# 6. Extract visible page text
# --------------------------------------------------

page_text = extract_visible_text(html)

text_input = pd.Series(
    [page_text],
    name=model["text_feature"]
)

# --------------------------------------------------
# 7. Generate URL branch prediction
# --------------------------------------------------

url_probability = model["url_model"].predict_proba(
    url_input
)[:, 1]

# --------------------------------------------------
# 8. Generate HTML branch prediction
# --------------------------------------------------

html_probability = model["html_model"].predict_proba(
    html_input
)[:, 1]

# --------------------------------------------------
# 9. Generate text branch prediction
# --------------------------------------------------

text_probability = model["text_model"].predict_proba(
    text_input
)[:, 1]

print("\nINDIVIDUAL BRANCH RESULTS")

print(
    "URL probability:",
    round(float(url_probability[0]), 4)
)

print(
    "HTML probability:",
    round(float(html_probability[0]), 4)
)

print(
    "Text probability:",
    round(float(text_probability[0]), 4)
)

# --------------------------------------------------
# 10. Prepare fusion input
# --------------------------------------------------

# IMPORTANT:
# Maintain the exact training-time order:
# 1. URL probability
# 2. HTML probability
# 3. Text probability

fusion_input = np.column_stack([
    url_probability,
    html_probability,
    text_probability
])

# Verify fusion input dimensions

if fusion_input.shape[1] != model["fusion_model"].n_features_in_:
    raise ValueError(
        "Fusion input dimension does not match "
        "the trained fusion model."
    )

# --------------------------------------------------
# 11. Generate final hybrid prediction
# --------------------------------------------------

hybrid_probability = model["fusion_model"].predict_proba(
    fusion_input
)[:, 1]

final_probability = float(hybrid_probability[0])

# --------------------------------------------------
# 12. Apply saved decision threshold
# --------------------------------------------------

threshold = float(model["threshold"])

prediction = (
    "PHISHING"
    if final_probability >= threshold
    else "LEGITIMATE"
)

# --------------------------------------------------
# 13. Display final results
# --------------------------------------------------

print("\n" + "=" * 55)
print("FINAL HYBRID PREDICTION")
print("=" * 55)

print(
    "URL probability:",
    round(float(url_probability[0]), 4)
)

print(
    "HTML probability:",
    round(float(html_probability[0]), 4)
)

print(
    "Text probability:",
    round(float(text_probability[0]), 4)
)

print("-" * 55)

print(
    "Fusion probability:",
    round(final_probability, 4)
)

print("Decision threshold:", threshold)

print("-" * 55)

print("FINAL CLASSIFICATION:", prediction)

print("=" * 55)

print("\nAll four model inference stages completed successfully.")

print(
    "\nNote: This is a synthetic demonstration input, "
    "not a validated real-world website assessment."
)