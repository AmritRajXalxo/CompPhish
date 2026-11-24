from pathlib import Path
import joblib

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "compphish_hybrid_model.joblib"

REQUIRED_KEYS = {
    "url_model",
    "html_model",
    "text_model",
    "fusion_model",
    "threshold",
    "url_features",
    "html_features",
    "text_feature",
}


def load_model_bundle(model_path: Path = DEFAULT_MODEL_PATH) -> dict:
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model file not found: {model_path}. "
            "Copy compphish_hybrid_model.joblib into the models folder."
        )

    bundle = joblib.load(model_path)

    if not isinstance(bundle, dict):
        raise TypeError("Expected the saved model bundle to be a dictionary.")

    missing = REQUIRED_KEYS.difference(bundle.keys())
    if missing:
        raise KeyError(f"Model bundle is missing required keys: {sorted(missing)}")

    return bundle
