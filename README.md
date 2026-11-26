# CompPhish — VS Code Application Scaffold

This project scaffold connects the trained CompPhish hybrid model to a FastAPI service and a Chrome Manifest V3 extension.

## Current project status

- Dataset integration, feature extraction for training, three branch models, OOF stacking, fusion, threshold selection, test evaluation and model export: reported as completed in the training workflow.
- This scaffold: created.
- Runtime feature parity with the training notebook: **must be verified before real predictions are trusted**.
- FastAPI API: scaffolded for precomputed features.
- Chrome extension: starter UI and request flow included; raw-page feature extraction is not yet wired to the trained feature definitions.

## 1. Open in VS Code

1. Extract `CompPhish_VSCode_Project.zip`.
2. Open the extracted `CompPhish_VSCode_Project` folder in VS Code.
3. Copy your trained model to:

   `models/compphish_hybrid_model.joblib`

   Source in Google Drive:

   `/content/drive/MyDrive/CompPhish DataSet/Model_Training/compphish_hybrid_model.joblib`

4. Open a terminal in the project root.

## 2. Create and activate the environment (Windows PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

## 3. Check scikit-learn compatibility

The model was serialized with joblib. Loading a scikit-learn model under a different scikit-learn version can produce warnings or errors.

In the Google Colab notebook where the model was trained, run:

```python
import sklearn, joblib, numpy, scipy
print("scikit-learn:", sklearn.__version__)
print("joblib:", joblib.__version__)
print("numpy:", numpy.__version__)
print("scipy:", scipy.__version__)
```

Install compatible versions locally. Do not blindly upgrade scikit-learn after exporting the model.

## 4. Start FastAPI

From the project root:

```powershell
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Open the interactive API documentation at `http://127.0.0.1:8000/docs`.

Health check: `GET http://127.0.0.1:8000/health`

## 5. Prediction API contract

`POST /predict` expects **precomputed features** in the exact feature names/order used by the training notebook:

```json
{
  "url_features": {
    "url_len": 30,
    "host_len": 15,
    "path_len": 10,
    "query_len": 0,
    "n_dots": 1,
    "n_hyphens": 0,
    "n_underscores": 0,
    "n_at": 0,
    "n_pct": 0,
    "n_amp": 0,
    "n_eq": 0,
    "n_slashes": 3,
    "n_subdomains": 0,
    "host_digits": 0,
    "host_has_ip": 0,
    "host_entropy": 2.5,
    "has_https": 1,
    "has_query": 0,
    "has_fragment": 0,
    "has_port": 0,
    "path_depth": 1,
    "suspicious_word_count": 0,
    "has_suspicious_word": 0,
    "is_url_shortener": 0,
    "has_punycode": 0,
    "url_entropy": 3.5,
    "digit_ratio": 0.0,
    "special_char_ratio": 0.1
  },
  "html_features": {
    "tag_count": 10,
    "form_count": 0,
    "input_count": 0,
    "password_fields": 0,
    "script_count": 1,
    "anchor_count": 2
  },
  "page_text": "Example visible webpage text"
}
```

The numeric values above are **illustrative only**, not an expected prediction. This endpoint is designed to test model loading and input shape. The values sent by a real browser must come from the exact training-time feature extraction functions.

## 6. Critical feature-parity requirement

The training project defined these 28 URL features and six HTML features, but this scaffold does not claim to reproduce the original extraction formulas. Before enabling raw-page scanning, copy the exact feature-extraction functions from the training notebook into `backend/feature_extraction.py` and add parity tests using saved training examples.

Do not substitute approximate features and then report the model's output as a valid prediction. Feature names alone are not enough: calculations, normalization, parsing rules and missing-value handling must match training.

The TF-IDF vectorizer is already part of the saved `text_model` pipeline. Send extracted page text as a string; do not fit a new vectorizer in the API.

## 7. Chrome extension

1. Start the backend locally.
2. Open Chrome and visit `chrome://extensions`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose the `extension` folder.

The extension is a UI scaffold. It currently reports that feature-parity integration is required; it does not silently use approximate feature extraction.

## 8. Files

- `backend/main.py`: FastAPI app, health route and hybrid prediction route.
- `backend/feature_extraction.py`: explicit placeholder for notebook-matched extractors.
- `backend/model_loader.py`: safe model-bundle loading and key checks.
- `extension/`: Manifest V3 popup scaffold.
- `tests/`: basic API tests.
- `requirements.txt`: Python dependencies.
- `MODEL_SETUP.md`: model-copy and compatibility instructions.

## 9. Responsible use

- Treat model output as a risk signal, not proof that a site is malicious.
- Do not automatically block sites in the first MVP.
- Do not send passwords, form values, cookies, authentication tokens or personal page data to the backend.
- Only send the minimum URL, structural counts and visible text needed for inference.
- Keep the local API bound to `127.0.0.1` during development.

## Scan evidence (Scam-link-check style results)

`POST /scan` now returns, next to the model score: a final verdict with a plain-language
explanation and next steps, redirect path, TLS certificate details, domain age (RDAP),
threat-feed lookups, page-behaviour findings, hosting IP / ASN / country, an estimated
network footprint, request statistics and community reports. `POST /report` and
`GET /reports?url=` store and read community reports.

Optional environment variables (each adds a threat-feed source when set):
`URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_KEY`. `COMPPHISH_DB` sets where community
reports are stored (default `/tmp/compphish_reports.db`, which is wiped on redeploy on
free hosts). The OpenPhish community feed needs no key. "No match" in a feed never means
"safe". The site screenshot is opt-in and uses the third-party service thum.io.
