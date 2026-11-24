# Model setup

Copy `compphish_hybrid_model.joblib` from Google Drive into this folder:

`models/compphish_hybrid_model.joblib`

Do not commit the model file to a public Git repository unless you have checked dataset/model sharing permissions.

The saved bundle is expected to contain:
- `url_model`
- `html_model`
- `text_model`
- `fusion_model`
- `threshold`
- `url_features`
- `html_features`
- `text_feature`

The backend validates these keys at startup.
