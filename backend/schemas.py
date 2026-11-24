from pydantic import BaseModel, Field
from typing import Dict


class PredictionRequest(BaseModel):
    url_features: Dict[str, float]
    html_features: Dict[str, float]
    page_text: str = Field(min_length=1, max_length=200_000)


class PredictionResponse(BaseModel):
    prediction: str
    phishing_probability: float
    risk_score: float
    threshold: float
    branch_probabilities: dict[str, float]
